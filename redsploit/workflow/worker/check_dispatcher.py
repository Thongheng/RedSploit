from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from redsploit.workflow.adapters.registry import get_adapter
from redsploit.workflow.services.command_runner import CommandRunner
from redsploit.workflow.schemas.workflow import DispatchRule
from redsploit.workflow.worker.checks import CheckDefinition, get_check_definition
from redsploit.workflow.worker.dispatcher import EndpointDescriptor, dispatch_checks

_NUCLEI_BATCH_SIZE = 100


@dataclass(slots=True)
class CheckResult:
    """Result of executing a security check against an endpoint."""

    check_id: str
    endpoint: str
    triggered: bool
    severity: str
    type: str
    evidence: dict[str, Any]
    trigger_rule: str


class CheckDispatcher:
    """
    Dispatches security checks to endpoints based on dispatch rules.

    This is the core of Phase 4 - Context Dispatch. It takes discovered endpoints,
    classifies them, evaluates dispatch rules, runs appropriate checks,
    and returns findings with deduplication.
    """

    def __init__(
        self,
        scan_id: str,
        publisher: Any | None = None,
        runner: CommandRunner | None = None,
    ):
        self.scan_id = scan_id
        self.publisher = publisher
        self.nuclei_adapter = get_adapter("nuclei")
        self.runner = runner or CommandRunner.from_settings()
        self._finding_cache: set[str] = set()  # For deduplication: "endpoint|check_id"

    def _publish_log(self, level: str, message: str) -> None:
        if self.publisher:
            self.publisher.publish(self.scan_id, level, message)

    def _is_duplicate(self, target: str, check_id: str) -> bool:
        """Check if this endpoint+check combination has already been flagged."""
        key = f"{target}|{check_id}"
        if key in self._finding_cache:
            return True
        self._finding_cache.add(key)
        return False

    @staticmethod
    def _target_for_endpoint(endpoint: EndpointDescriptor) -> str:
        if not endpoint.params:
            return endpoint.url
        return f"{endpoint.url}?{urlencode(endpoint.params)}"

    def dispatch_for_endpoint(
        self,
        endpoint: EndpointDescriptor,
        rules: list[DispatchRule],
    ) -> list[CheckResult]:
        """
        Evaluate dispatch rules for a single endpoint and run matching checks.

        Args:
            endpoint: The endpoint descriptor with URL, method, params, etc.
            rules: List of dispatch rules from the workflow

        Returns:
            List of check results (findings)
        """
        # Get list of checks to run based on endpoint classification
        check_ids = dispatch_checks(endpoint, rules)

        if not check_ids:
            self._publish_log("info", f"No checks matched for {endpoint.url}")
            return []

        self._publish_log(
            "info",
            f"Dispatching {len(check_ids)} checks for {endpoint.url}: {', '.join(check_ids)}"
        )

        results: list[CheckResult] = []

        for check_id in check_ids:
            # Deduplication: skip if we've already checked this endpoint
            target = self._target_for_endpoint(endpoint)
            if self._is_duplicate(target, check_id):
                self._publish_log("debug", f"Skipping duplicate check {check_id} for {endpoint.url}")
                continue

            result = self._run_check(endpoint, check_id, rules)
            if result:
                results.append(result)

        return results

    def _run_check(
        self,
        endpoint: EndpointDescriptor,
        check_id: str,
        rules: list[DispatchRule],
    ) -> CheckResult | None:
        """Execute a single check against an endpoint."""
        check_def = get_check_definition(check_id)

        if not check_def:
            self._publish_log("warn", f"Unknown check '{check_id}' - skipping")
            return CheckResult(
                check_id=check_id,
                endpoint=endpoint.url,
                triggered=False,
                severity="info",
                type="unknown_check",
                evidence={"error": f"Check '{check_id}' not found in registry"},
                trigger_rule=self._get_trigger_rule(check_id, rules),
            )

        self._publish_log("info", f"Running {check_id} against {endpoint.url}")

        try:
            target = self._target_for_endpoint(endpoint)

            # Execute the check using the appropriate adapter
            if check_def.tool == "nuclei":
                triggered, evidence = self.nuclei_adapter.execute_targeted(
                    target=target,
                    template_id=check_def.template_id,
                    runner=self.runner,
                )
            else:
                triggered = False
                evidence = {"error": f"Tool '{check_def.tool}' not yet supported"}

            if triggered:
                self._publish_log(
                    "info",
                    f"[FINDING] {check_def.description} on {endpoint.url}"
                )

            return CheckResult(
                check_id=check_id,
                endpoint=endpoint.url,
                triggered=triggered,
                severity=check_def.severity,
                type=check_def.id,
                evidence=evidence,
                trigger_rule=self._get_trigger_rule(check_id, rules),
            )

        except Exception as e:
            self._publish_log("error", f"Check {check_id} failed: {str(e)}")
            return CheckResult(
                check_id=check_id,
                endpoint=endpoint.url,
                triggered=False,
                severity="info",
                type="check_error",
                evidence={"error": str(e)},
                trigger_rule=self._get_trigger_rule(check_id, rules),
            )

    def _get_trigger_rule(self, check_id: str, rules: list[DispatchRule]) -> str:
        """Find which rule triggered this check."""
        for rule in rules:
            if check_id in rule.checks:
                if rule.always:
                    return "always"
                return rule.condition or "unknown"
        return "unknown"

    def dispatch_batch(
        self,
        endpoints: list[EndpointDescriptor],
        rules: list[DispatchRule],
    ) -> list[CheckResult]:
        """
        Dispatch checks for a batch of endpoints.

        Args:
            endpoints: List of endpoint descriptors
            rules: List of dispatch rules from the workflow

        Returns:
            List of all check results (only triggered findings)
        """
        self._publish_log("info", f"Dispatching checks for {len(endpoints)} endpoints")
        all_results = self._dispatch_nuclei_batches(endpoints, rules)
        for endpoint in endpoints:
            fallback_results = self._dispatch_fallback_checks(endpoint, rules)
            all_results.extend([r for r in fallback_results if r.triggered])

        self._publish_log(
            "info",
            f"Batch complete: {len(all_results)} findings from {len(endpoints)} endpoints"
        )

        return all_results

    def _dispatch_nuclei_batches(
        self,
        endpoints: list[EndpointDescriptor],
        rules: list[DispatchRule],
    ) -> list[CheckResult]:
        grouped: dict[str, list[tuple[EndpointDescriptor, str, CheckDefinition]]] = {}

        for endpoint in endpoints:
            check_ids = dispatch_checks(endpoint, rules)
            if not check_ids:
                self._publish_log("info", f"No checks matched for {endpoint.url}")
                continue

            self._publish_log(
                "info",
                f"Dispatching {len(check_ids)} checks for {endpoint.url}: {', '.join(check_ids)}"
            )

            for check_id in check_ids:
                check_def = get_check_definition(check_id)
                if check_def is None or check_def.tool != "nuclei":
                    continue
                target = self._target_for_endpoint(endpoint)
                if self._is_duplicate(target, check_id):
                    self._publish_log("debug", f"Skipping duplicate check {check_id} for {endpoint.url}")
                    continue
                grouped.setdefault(check_id, []).append((endpoint, target, check_def))

        results: list[CheckResult] = []
        for check_id, entries in grouped.items():
            check_def = entries[0][2]
            for offset in range(0, len(entries), _NUCLEI_BATCH_SIZE):
                chunk = entries[offset: offset + _NUCLEI_BATCH_SIZE]
                targets = [target for _, target, _ in chunk]
                self._publish_log("info", f"Running {check_id} against {len(targets)} target(s)")
                batch_results = self.nuclei_adapter.execute_targeted_batch(
                    targets=targets,
                    template_id=check_def.template_id,
                    runner=self.runner,
                )

                for endpoint, target, _ in chunk:
                    triggered, evidence = batch_results.get(
                        target,
                        (False, {"error": "Target missing from nuclei batch results"}),
                    )
                    if not triggered:
                        continue
                    self._publish_log("info", f"[FINDING] {check_def.description} on {endpoint.url}")
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            endpoint=endpoint.url,
                            triggered=True,
                            severity=check_def.severity,
                            type=check_def.id,
                            evidence=evidence,
                            trigger_rule=self._get_trigger_rule(check_id, rules),
                        )
                    )

        return results

    def _dispatch_fallback_checks(
        self,
        endpoint: EndpointDescriptor,
        rules: list[DispatchRule],
    ) -> list[CheckResult]:
        results: list[CheckResult] = []
        for check_id in dispatch_checks(endpoint, rules):
            check_def = get_check_definition(check_id)
            if check_def is not None and check_def.tool == "nuclei":
                continue
            if self._is_duplicate(self._target_for_endpoint(endpoint), check_id):
                self._publish_log("debug", f"Skipping duplicate check {check_id} for {endpoint.url}")
                continue
            result = self._run_check(endpoint, check_id, rules)
            if result:
                results.append(result)
        return results

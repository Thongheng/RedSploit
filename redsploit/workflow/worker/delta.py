from __future__ import annotations

from redsploit.workflow.schemas.delta import DeltaSummary, HostChangeSummary, HostFingerprint


def summarize_delta(
    target_name: str,
    previous: list[HostFingerprint],
    current: list[HostFingerprint],
) -> DeltaSummary:
    previous_by_host = {item.host: item for item in previous}
    current_by_host = {item.host: item for item in current}

    new_hosts = sorted(set(current_by_host) - set(previous_by_host))
    removed_hosts = sorted(set(previous_by_host) - set(current_by_host))
    changed_hosts: list[HostChangeSummary] = []

    for host in sorted(set(previous_by_host) & set(current_by_host)):
        old = previous_by_host[host]
        new = current_by_host[host]
        tech_added = sorted(set(new.tech_stack) - set(old.tech_stack))
        tech_removed = sorted(set(old.tech_stack) - set(new.tech_stack))
        js_added = sorted(set(new.js_files) - set(old.js_files))
        js_removed = sorted(set(old.js_files) - set(new.js_files))
        hash_changed = (old.response_hash != new.response_hash) or (old.headers_hash != new.headers_hash)

        if tech_added or tech_removed or js_added or js_removed or hash_changed:
            changed_hosts.append(
                HostChangeSummary(
                    host=host,
                    tech_added=tech_added,
                    tech_removed=tech_removed,
                    js_added=js_added,
                    js_removed=js_removed,
                    hash_changed=hash_changed,
                )
            )

    return DeltaSummary(
        target_name=target_name,
        new_hosts=new_hosts,
        removed_hosts=removed_hosts,
        changed_hosts=changed_hosts,
    )


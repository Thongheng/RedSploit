
import time
from rich.console import Console
from redsploit.workflow.live_step_view import LiveStepView
from redsploit.workflow.schemas.scan import StepRun, StepTelemetry

def test_live():
    console = Console()
    view = LiveStepView(console, total_steps=3)
    
    with view:
        time.sleep(1)
        
        step1 = StepRun(id="nmap_scan", tool="nmap", kind="tool", status="running")
        view.step_started(step1)
        time.sleep(1)
        view.update_last_line("nmap_scan", "Scanning port 80...")
        time.sleep(1)
        view.update_last_line("nmap_scan", "Scanning port 443...")
        time.sleep(1)
        
        step1.status = "complete"
        step1.telemetry = StepTelemetry(output_count=2, duration_ms=5000)
        view.step_done(step1, "complete")
        
        step2 = StepRun(id="dirsearch", tool="dirsearch", kind="tool", status="running")
        view.step_started(step2)
        time.sleep(1)
        view.update_last_line("dirsearch", "Found /admin")
        time.sleep(1)
        
        step2.status = "failed"
        step2.error_summary = "Connection refused"
        view.step_done(step2, "failed")
        
        time.sleep(2)

if __name__ == "__main__":
    test_live()

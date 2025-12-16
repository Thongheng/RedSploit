import os
import subprocess
import yaml
import time
from typing import List, Dict, Optional
from .colors import Colors, log_success, log_error, log_warn, log_info

class PlaybookManager:
    def __init__(self, session):
        self.session = session
        # Playbooks stored in playbooks/ at project root
        self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.playbooks_dir = os.path.join(self.project_root, "playbooks")
        
        if not os.path.exists(self.playbooks_dir):
            os.makedirs(self.playbooks_dir, exist_ok=True)

    def list_playbooks(self):
        """List available playbooks."""
        files = [f for f in os.listdir(self.playbooks_dir) if f.endswith('.yaml') or f.endswith('.yml')]
        
        if not files:
            print("No playbooks found in 'playbooks/' directory.")
            return

        print(f"\n{Colors.HEADER}Available Playbooks{Colors.ENDC}")
        print("=" * 40)
        for f in sorted(files):
            name = f
            # Try to read description
            try:
                with open(os.path.join(self.playbooks_dir, f), 'r') as pf:
                    data = yaml.safe_load(pf)
                    desc = data.get('description', '')
                    name = data.get('name', f)
            except:
                desc = "Error reading file"

            print(f"{f:<20} {desc}")
        print("")

    def run_playbook(self, playbook_name: str):
        """Execute a playbook."""
        # Handle file extension
        if not playbook_name.endswith('.yaml') and not playbook_name.endswith('.yml'):
            playbook_name += ".yaml"
            
        path = os.path.join(self.playbooks_dir, playbook_name)
        
        if not os.path.exists(path):
            log_error(f"Playbook '{playbook_name}' not found.")
            return

        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            log_error(f"Failed to load playbook: {e}")
            return

        print(f"\n{Colors.HEADER}Running Playbook: {data.get('name', playbook_name)}{Colors.ENDC}")
        print(f"{data.get('description', '')}\n")

        steps = data.get('steps', [])
        for i, step in enumerate(steps):
            step_name = step.get('name', f"Step {i+1}")
            cmd_template = step.get('cmd', '')
            desc = step.get('description', '')
            
            print(f"{Colors.BOLD}[Step {i+1}/{len(steps)}] {step_name}{Colors.ENDC}")
            if desc:
                print(f"Description: {desc}")
            
            # Variable Injection
            # We use session.env to format the command string
            try:
                # Add extra dynamic vars
                context = self.session.env.copy()
                domain, url, port = self.session.resolve_target()
                context['url'] = url if url else ""
                context['domain'] = domain if domain else ""
                context['hash'] = self.session.get("hash")
                
                # Check for Loot iteration? (Future scope)
                
                cmd = cmd_template.format(**context)
            except KeyError as e:
                log_error(f"Missing variable for command: {e}")
                log_warn(f"Command template: {cmd_template}")
                if input("Continue anyway? (y/n) ").lower() != 'y':
                    break
                continue
            
            print(f"Command: {Colors.OKCYAN}{cmd}{Colors.ENDC}")
            
            # Interactive Check
            action = input("[E]xecute, [S]kip, [Q]uit? ").lower()
            
            if action == 'q':
                break
            elif action == 's':
                log_warn("Skipping step...")
                continue
            elif action == 'e' or action == '':
                try:
                    log_info(f"Executing: {cmd}")
                    subprocess.run(cmd, shell=True, check=True)
                    log_success("Step complete.")
                except subprocess.CalledProcessError as e:
                     log_error(f"Step failed with exit code {e.returncode}")
                except Exception as e:
                     log_error(f"Execution error: {e}")
            else:
                log_error("Invalid choice.")
        
        print("\nPlaybook execution finished.")

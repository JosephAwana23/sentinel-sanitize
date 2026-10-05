import queue
import threading
import time
import json

class AISentinelQueue:
    """Thread-safe queue that sends sanitized logs to the AI for triage briefings."""
    
    def __init__(self):
        self.log_queue = queue.Queue()
        # Start the background worker thread
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def submit_to_ai(self, sanitized_log: dict):
        """Puts the scrubbed log into the queue."""
        self.log_queue.put(sanitized_log)

    def _generate_ai_briefing(self, log_data: dict):
        """Placeholder where you will drop your google-generativeai API code."""
        print("\n=== [ AI SOC BRIEFING GENERATED ] ===")
        print("CONTEXT: Telemetry is fully sanitized. No PII/PCI leaked to AI.")
        alerts = log_data.get("threat_metadata", {}).get("alerts", [])
        
        if alerts:
            tactic = alerts[0].get("tactic", "Unknown")
            print(f"AI ANALYSIS: Detected '{tactic}' behavior. "
                  f"The actor attempted to leverage {alerts[0].get('technique', 'an exploit')}.")
            print("RECOMMENDATION: Verify quarantine rules and audit firewall logs.")
        print("======================================\n")

    def _process_queue(self):
        """Runs continuously in the background, exactly like Ghost Aegis."""
        while True:
            try:
                # Wait for a log to enter the queue
                log_data = self.log_queue.get()
                
                # Simulate the delay of an API call to Gemini/OpenAI
                time.sleep(1) 
                
                # Generate the report
                self._generate_ai_briefing(log_data)
                
                # Mark the task as done
                self.log_queue.task_done()
            except Exception as e:
                print(f"[!] AI Queue Error: {e}")
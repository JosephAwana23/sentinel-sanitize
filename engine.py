import re
import json
import hashlib
import platform
import subprocess
from typing import Dict, Any, List

class SecurityEngine:
    """V2 Engine: Scrubbing, MITRE Mapping, Crypto-Chaining, and Active Quarantine."""

    RFC1918_REGEX = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
    PAN_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    DETECTION_RULES = [
        {"id": "T1110.001", "technique": "Password Guessing", "tactic": "Credential Access", "keywords": ["failed login", "invalid credentials"], "severity": "MEDIUM"},
        {"id": "T1059.001", "technique": "PowerShell Execution", "tactic": "Execution", "keywords": ["powershell.exe -enc", "downloadstring"], "severity": "HIGH"},
        {"id": "T1046", "technique": "Network Service Discovery", "tactic": "Discovery", "keywords": ["port scan", "syn scan", "nmap"], "severity": "LOW"},
    ]

    def __init__(self):
        # 1. Initialize the Cryptographic Chain (Genesis Block)
        self.previous_hash = hashlib.sha256(b"SENTINEL_GENESIS_BLOCK").hexdigest()

    @staticmethod
    def is_luhn_valid(card_number: str) -> bool:
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19: return False
        checksum = 0
        for idx, digit in enumerate(digits[::-1]):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else: checksum += digit
        return checksum % 10 == 0

    def scrub_text(self, text: str) -> str:
        if not isinstance(text, str): return text
        text = self.RFC1918_REGEX.sub("[INTERNAL_IP_MASKED]", text)
        def replace_card(match):
            raw = match.group(0)
            cleaned = re.sub(r"[^\d]", "", raw)
            if self.is_luhn_valid(cleaned):
                return f"[CARD_REDACTED_****{cleaned[-4:]}]"
            return raw
        return self.PAN_CANDIDATE_REGEX.sub(replace_card, text)

    def sanitize_log(self, record: Any) -> Any:
        if isinstance(record, dict): return {k: self.sanitize_log(v) for k, v in record.items()}
        elif isinstance(record, list): return [self.sanitize_log(elem) for elem in record]
        elif isinstance(record, str): return self.scrub_text(record)
        return record

    def correlate_mitre(self, log_str: str) -> List[Dict[str, str]]:
        lowered = log_str.lower()
        return [rule for rule in self.DETECTION_RULES if any(kw in lowered for kw in rule["keywords"])]

    def secure_hash_log(self, sanitized_data: Dict) -> str:
        """2. Creates a tamper-proof hash linking to the previous log."""
        payload_str = json.dumps(sanitized_data, sort_keys=True)
        chain_data = self.previous_hash + payload_str
        current_hash = hashlib.sha256(chain_data.encode()).hexdigest()
        self.previous_hash = current_hash  # Update chain
        return current_hash

    def active_quarantine(self, threat_ip: str):
        """3. Air-Gaps the host if critical threats are detected."""
        print(f"\n[!!!] CRITICAL THREAT DETECTED: Initiating Active Defense against {threat_ip}")
        os_type = platform.system()
        
        try:
            if os_type == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="SENTINEL_BLOCK_{threat_ip}" dir=in action=block remoteip={threat_ip}'
                print(f"      [DRY-RUN] Windows Command: {cmd}")
            elif os_type == "Linux":
                cmd = f'sudo iptables -A INPUT -s {threat_ip} -j DROP'
                print(f"      [DRY-RUN] Linux Command: {cmd}")
            else:
                print("      [!] OS not supported for automated quarantine.")
        except Exception as e:
            print(f"      [!] Quarantine failed: {e}")

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = self.sanitize_log(raw_event)
        detections = self.correlate_mitre(json.dumps(sanitized))
        
        # Calculate cryptographic chain hash
        crypto_hash = self.secure_hash_log(sanitized)

        # Evaluate threat severity and trigger quarantine
        needs_investigation = len(detections) > 0
        if needs_investigation:
            highest_severity = max([d["severity"] for d in detections], key=lambda s: {"LOW":1, "MEDIUM":2, "HIGH":3, "CRITICAL":4}.get(s, 0))
            if highest_severity in ["HIGH", "CRITICAL"]:
                # Trigger Active Defense! Pull the threat IP if available.
                threat_ip = raw_event.get("threat_ip", "UNKNOWN")
                self.active_quarantine(threat_ip)

        sanitized["threat_metadata"] = {
            "alerts": detections,
            "needs_investigation": needs_investigation,
            "crypto_chain_hash": crypto_hash
        }
        return sanitized
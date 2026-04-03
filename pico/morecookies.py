import requests
from base64 import b64decode, b64encode
from utils.pretty_print import pretty_print

url = "http://wily-courier.picoctf.net:52667"

data = "VmpuUUswUEl5b0xaOFpZek9pbXhoamp6Si9vWDVCcmhNK1ZURzNMSWVrcGxra1R3TjZQcGpQbE5zb3pvYjY2dW9zajFnaUVkTnlJalhaZUxycDJzWndiR0FTWjJIeGN5UGJWelR2ZUY0R3FYKzh1SGFpNzZBM0xLaG16N0JHQzk="
decoded_data = b64decode(b64decode(data).decode())
#turn into byte array
bytes_data = bytearray(decoded_data)

mask = 0b01
for i in range(len(bytes_data)):
    cookie = bytearray(decoded_data)
    cookie[i] ^= mask
    cookie_encoded = b64encode(b64encode(cookie))
    cookie_decoded = cookie_encoded.decode('utf-8')
    
    cookies = {
    "auth_name":cookie_decoded
    }
    
    res = requests.get(url, cookies=cookies)
    if 'picoCTF{' in res.text:
        pretty_print(res)
    



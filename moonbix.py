import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
from time import time , sleep
import requests
import random
import uuid
from fake_useragent import UserAgent
from urllib.parse import quote

def random_string(length):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choice(chars) for _ in range(length))

def gen_cookies():
    cookies = {
                'theme': random.choice(['dark', 'light']),
                'bnc-uuid': str(uuid.uuid4()),
                'sensorsdata2015jssdkcross': quote((base64.b64encode(random_string(64).encode()).decode()), safe=''),
                'userPreferredCurrency': random.choice(['USD_USD', 'EUR_EUR', 'GBP_GBP']),
                'BNC_FV_KEY': random_string(32),
                '_gid': f'GA1.2.{random.randint(1000000000, 9999999999)}.{random.randint(1000000000, 9999999999)}',
                'BNC_FV_KEY_T': f'101-{random_string(10)}-{random_string(10)}-{random_string(10)}',
                'BNC_FV_KEY_EXPIRE': str(random.randint(1727090000000, 1727099999999)), 
                'OptanonConsent': f'isGpcEnabled={random.randint(0, 1)}&datestamp=Mon+Sep+23+2024+{random.randint(0, 23)}%3A{random.randint(0, 59)}%3A{random.randint(0, 59)}+GMT%2B{random.randint(-12, 14)}00+(Random+Time)&version=202407.2.0&browserGpcFlag={random.randint(0, 1)}&isIABGlobal={random.choice(["true", "false"])}&hosts=&consentId={str(uuid.uuid4())}&interactionCount={random.randint(0, 10)}&isAnonUser={random.randint(0, 1)}&landingPath=NotLandingPage&groups=C0001%3A{random.randint(1, 3)}%2CC0003%3A{random.randint(1, 3)}%2CC0004%3A{random.randint(1, 3)}%2CC0002%3A{random.randint(1, 3)}&AwaitingReconsent={random.choice(["true", "false"])}',
                '_gat_UA-162512367-1': str(random.randint(0, 1)),
                '_ga': f'GA1.1.{random.randint(1000000000, 9999999999)}.{random.randint(1000000000, 9999999999)}',
                '_ga_3WP50LGEEC': f'GS1.1.{random.randint(1727000000, 1728000000)}.{random.randint(0, 10)}.{random.randint(1727000000, 1728000000)}.{random.randint(0, 100)}.0.0',
            }
    return cookies

def gen_headers():
    ua = UserAgent()
    headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'bnc-location': '',
                'bnc-uuid': str(uuid.uuid4()), 
                'cache-control': 'no-cache',
                'clienttype': 'web',
                'content-type': 'application/json',
                'csrftoken': random_string(32),
                'device-info': base64.b64encode(random_string(64).encode()).decode(),
                'fvideo-id': str(uuid.uuid4()), 
                'fvideo-token': random_string(64),
                'lang': 'en',
                'origin': 'https://www.binance.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://www.binance.com/en/game/tg/moon-bix',
                'sec-ch-ua': f'"{random_string(10)}";v="{random.randint(70, 130)}", "{random_string(10)}";v="{random.randint(70, 130)}", "Not.A/Brand";v="{random.randint(20, 30)}"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': f'"{random_string(10)}"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': ua.random,
                'x-passthrough-token': '',
                'x-trace-id': str(uuid.uuid4()), 
                'x-ui-request-trace': str(uuid.uuid4()), 
            }
    return headers


def process_item_settings(item_settings):
    processed_items = []
    for item in item_settings:
        #item_type = item["type"]
        speed = item["speed"]
        size = item["size"]
        quantity = item["quantity"]
        reward_values = "|".join(map(str, item["rewardValueList"]))
        #if you more extra score 
        #here requires some maths knowledge  to calculate the coordinates
        processed_items.append(f"{int(time()*1000)}|{speed}|{size}|{quantity}|{reward_values}")
    return ";".join(processed_items)


def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length) 
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    return f"{iv_b64}{ciphertext_b64}"

def Authenticate(tgWebAppData):
    json_data = {
        'queryString': tgWebAppData,
        'socialType': 'telegram',
    }
    response = requests.post(
        'https://www.binance.com/bapi/growth/v1/friendly/growth-paas/third-party/access/accessToken',
        cookies=gen_cookies(),
        headers=gen_headers(),
        json=json_data,
    )
    return response.json()

def getTaskList(accessToken):
    header = gen_headers()
    cookies = gen_cookies()
    header.update({'x-growth-token': accessToken})
    json_data = {
            'resourceId': 2056,
        }
    response = requests.post(
            'https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/task/list',
            cookies=cookies,
            headers=header,
            json=json_data,
        )
    return response.json()
    
def completeTask(accessToken,taskId):
    header = gen_headers()
    cookies = gen_cookies()
    header.update({'x-growth-token': accessToken})
    json_data = {
            'resourceIdList': [
                taskId,# task Id from Task Lists
            ],
            'referralCode': None,
        }
    response = requests.post(
            'https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/task/complete',
            cookies=cookies,
            headers=header,
            json=json_data,
        )
    return response.json()


def playGame(accessToken):
    json_data = {
        'resourceId': 2056,
    }
    header = gen_headers()
    cookies = gen_cookies()
    header.update({'x-growth-token': accessToken})
    response = requests.post(
        'https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/game/start',
        cookies=cookies,
        headers=header,
        json=json_data,
    )
    o = response.json()['data']
    dataToMap =  o["cryptoMinerConfig"]["itemSettingList"]
    key = binascii.unhexlify(o['gameTag'])
    payload = encrypt_data((process_item_settings(dataToMap)).encode('utf-8'),key)
    #sleep(10) uncomment this to add 10 seconds delay after the starts 
    json_data = {
            'resourceId': 2056,
            'payload':payload,
            'log': 160,#check line 76 to set custom value
        }

    response = requests.post(
            'https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/game/complete',
            cookies=cookies,
            headers=header,
            json=json_data,
        )
    return response.json()

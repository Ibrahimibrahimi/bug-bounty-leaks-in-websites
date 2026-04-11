import requests
import json


def send_practice_session():
    url = 'https://cag.chessly.com/beta/progress/openings/practice/sessions'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Content-Type': 'application/json',
        'Content-Length': '72',  # Optional, requests will set this automatically
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': '__Secure-cst=F_Lv_QNTtJmRr_8EZ0n_aL3Qtr1gpmJKwjNV1hkSi2ge; _ga=GA1.1.953203769.1775914150; _ga_PNQ0H99BWZ=GS2.1.s1775914150$o1$g1$t1775915767$j27$l0$h0',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
    }

    data = {
        "courseId": "6cdd46e2-7bff-4f8b-bfcf-aeddd9745e6c",
        "variationsCount": 22
    }

    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()  # Raise exception if request failed
    return response.json()


o = []
for i in range(50):
    o.append(send_practice_session())
print(o)

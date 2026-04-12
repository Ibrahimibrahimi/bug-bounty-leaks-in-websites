import uuid
import requests
import time


def getCookies(email="eldoradogpt2025@gmail.com", password="JT1215060000"):
    # "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775757980$j36$l0$h0;"
    COOKIE = "_ga=GA1.1.848658436.1776009052; _ga_PNQ0H99BWZ=GS2.1.s1776009052$o1$g1$t1776009160$j8$l0$h0;"
    url = "https://cag.chessly.com/beta/login"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Content-Type": "application/json",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": COOKIE,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }
    payload = {
        "email": email,
        "password": password
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        cst_cookie = response.cookies.get('__Secure-cst')
        # print(f"========>", cst_cookie)
        COOKIE += f"__Secure-cst={cst_cookie}"
        return COOKIE
    except requests.RequestException as e:
        print("Cant get cookie",e)
        exit()


def v(ui="775a4eea-5a50-47da-b7dd-5790ef829fbe"):
    url = "https://cag.chessly.com/beta/bots/games"

    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Content-Type": "application/json",
        "Content-Length": "356",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": getCookies(),
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }

    json_body = {
        "sanMoves": ["d4", "d5"],
        "botCourse": ui,
        "botDifficulty": "easy",
        "deviationMoveIndex": 0,
        "lastFEN": "rnbqkbnr/ppp1pppp/8/3p4/3P4/8/PPP1PPPP/RNBQKBNR w KQkq d6 0 2",
        "startFEN": "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
        "userColor": "w",
        "winnerColor": "b",
        "settings": {
            "deviationEnabled": True,
            "courseChapters": []
        }
    }

    response = requests.post(url, headers=headers, json=json_body)

    print(response.status_code)
    print(response.text)

while True :
    v(input("Bot uuid : "))
"""
fb973fb9-8cb3-4ac4-9ed0-42f882cf9a2b
775a4eea-5a50-47da-b7dd-5790ef829fbe
"""

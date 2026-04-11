import requests
import time


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
    "Cookie": "_ga=GA1.1.1228811036.1775936797; _ga_PNQ0H99BWZ=GS2.1.s1775936797$o1$g1$t1775936851$j8$l0$h0; __Secure-cst=gSHMwiUNXoNjG_1yPCSwzqTgObQ9LWgDaFMfCmfNP7b",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site"
}

json_body = {
    "sanMoves": ["d4", "d5"],
    "botCourse": "775a4eea-5a50-47da-b7dd-5790ef829fbe",
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
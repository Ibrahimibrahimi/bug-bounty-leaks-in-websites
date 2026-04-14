import requests
import json


def send_chessly_game(
    botCourse="7723083f-a0d5-4006-bb1a-78402ea0becd",
    lastFEN="7Q/8/8/8/7k/4K3/5P1P/6R1 b - - 10 48",
    botDifficulty="easy",
    winnerColor="w",
    moves=["e4", "e5", "Nf3", "Nc6", "d4", "d5", "exd5", "Bg4", "dxc6", "exd4", "cxb7", "Rb8", "Qxd4", "Bxf3", "Qxd8+", "Rxd8", "gxf3", "Rb8", "Ba6", "Bb4+", "Nc3", "Nf6", "a3", "O-O", "axb4", "Rfe8+", "Be3", "Re6", "O-O-O", "Rxa6", "b5", "Ra1+", "Kd2", "Rxd1+", "Rxd1", "Rxb7", "Ke2", "g6", "Nd5", "Rxb5", "Nxf6+", "Kg7", "Bd4", "Kf8", "Nd7+", "Ke7",
           "Ne5", "f6", "Nc6+", "Kd7", "Nxa7", "Rxb2", "Bxb2+", "Ke6", "Nc6", "h5", "Bxf6", "Kxf6", "Rd7", "Ke6", "Rd3", "g5", "Ke3", "Kf5", "Rd4", "g4", "fxg4+", "Kg5", "gxh5", "Kxh5", "Rf4", "Kg5", "Nd4", "c5", "c4", "cxd4+", "Rxd4", "Kf5", "c5", "Ke5", "c6", "Ke6", "c7", "Ke5", "c8=Q", "Kf6", "Re4", "Kg5", "Qf8", "Kg6", "Rg4+", "Kh5", "Rg1", "Kh4", "Qh8#"]
):
    url = "https://cag.chessly.com/beta/bots/games"

    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Content-Type": "application/json",
        "Content-Length": "918",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.1007278005.1776185209; _ga_PNQ0H99BWZ=GS2.1.s1776185208$o1$g1$t1776185636$j60$l0$h0; __Secure-cst=FuUwdtR0HcIFLUfrvFMSIJOSLCWrsDXz-usYdRX99hxv",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    body = {
        "sanMoves": moves,
        "botCourse": botCourse,
        "botDifficulty": botDifficulty,
        "deviationMoveIndex": 6,
        "lastFEN": lastFEN,
        "startFEN": "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
        "userColor": winnerColor ,
        "winnerColor": winnerColor,
        "settings": {
            "deviationEnabled": True,
            "courseChapters": []
        }
    }

    response = requests.post(url, headers=headers, json=body)

    # Print response status and content
    print(f"Status Code: {response.status_code}")
    print("Response Body:")
    print(response.text)



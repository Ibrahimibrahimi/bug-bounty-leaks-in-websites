
import requests

def get_new_variations(uuid):
    url = f"https://cag.chessly.com/beta/openings/paths/studies/{uuid}/tiles/0"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.772810061.1776173872; _ga_PNQ0H99BWZ=GS2.1.s1776173871$o1$g1$t1776177282$j53$l0$h0; __Secure-cst=VNtB5i6NivewW1EH6frEDor-I5oX-JEYmi5WIJC8Bg09",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Content-Length": "0"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data.get("newVariations", [])
    else:
        print(f"Request failed with status code {response.status_code}")
        return []

if __name__ == "__main__" :
  print(get_new_variations(input("Enter Study id to get its variations : ")))
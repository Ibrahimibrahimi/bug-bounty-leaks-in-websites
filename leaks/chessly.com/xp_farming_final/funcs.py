import requests
import time


# get all openings courses
def get_openings_courses():
    url = "https://cag.chessly.com/beta/openings/courses"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.772810061.1776173872; _ga_PNQ0H99BWZ=GS2.1.s1776173871$o1$g1$t1776178278$j42$l0$h0; __Secure-cst=VNtB5i6NivewW1EH6frEDor-I5oX-JEYmi5WIJC8Bg09",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Request failed with status code {response.status_code}")
        return []

    data = response.json()

    ids = [item['id'] for item in data]
    return ids

# lesson ==> chapters


def extract_chapter_from_course(uuid):
    url = f"https://cag.chessly.com/beta/openings/courses/{uuid}/chapters"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.772810061.1776173872; _ga_PNQ0H99BWZ=GS2.1.s1776173871$o1$g1$t1776178278$j42$l0$h0; __Secure-cst=VNtB5i6NivewW1EH6frEDor-I5oX-JEYmi5WIJC8Bg09",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        # Extract all id values
        ids = [item.get("id") for item in data if "id" in item]
        return ids
    else:
        print(f"Request failed with status code {response.status_code}")
        return []


# chapter ==> studyId
def extract_study_from_chapter(uuid):
    url = f"https://cag.chessly.com/beta/openings/courses/chapters/{uuid}/studies"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.772810061.1776173872; _ga_PNQ0H99BWZ=GS2.1.s1776173871$o1$g1$t1776178278$j42$l0$h0; __Secure-cst=VNtB5i6NivewW1EH6frEDor-I5oX-JEYmi5WIJC8Bg09",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }
    # print(url)
    response = requests.get(url, headers=headers)
    print(response.text)
    if response.status_code == 200:
        data = response.json()
        # Extract all studyId values
        study_ids = [item.get("id") for item in data if "id" in item]
        return study_ids
    else:
        print(f"Request failed with status code {response.status_code}")
        return []

# study ==> variations


def extract_variation_from_study(uuid):
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

# variation ==> read variation


def readVariation(uuid):
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}"

    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.772810061.1776173872; _ga_PNQ0H99BWZ=GS2.1.s1776173871$o1$g1$t1776175581$j48$l0$h0; __Secure-cst=VNtB5i6NivewW1EH6frEDor-I5oX-JEYmi5WIJC8Bg09",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    response = requests.post(url, headers=headers)
    print(response.status_code)
    # print("Response Body:", response.text)
    if response.status_code == 200:
        # check the points
        points = response.json().get("points", 0)
        print("You got ", points)
        time.sleep(2)
        # print("Status Code:", response.status_code)
        if points > 0:
            # re read the lesson
            print(" Re Reading the same lesson ")
            readVariation(uuid)
        else:
            print("Enought points")

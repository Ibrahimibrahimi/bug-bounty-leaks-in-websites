
import requests , time

# extract cookie
def getCookies(email="eldoradogpt2025@gmail.com", password="JT1215060000"):
    COOKIE = "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775757980$j36$l0$h0;"
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
        COOKIE += f"__Secure-cst={cst_cookie}"
        return COOKIE
    except requests.RequestException as e:
        print("Cant get cookie")
        exit()


def getOpenningCourses(cookie: str):
    url = 'https://cag.chessly.com/beta/openings/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': cookie,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception if the request failed
    data = response.json()

    # Extract IDs
    ids = [item['id'] for item in data]
    return ids

def getLegacyCourses(cookie: str):
    url = 'https://cag.chessly.com/beta/legacy/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': cookie,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception if the request failed
    data = response.json()

    # Extract IDs
    ids = [item['id'] for item in data]
    return ids

def getProgressLesosns(cookie: str):
    url = 'https://cag.chessly.com/beta/progress/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': cookie,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception if the request failed
    data = response.json()

    # Extract IDs
    ids = [item['id'] for item in data]
    return ids


def readLesson(uuid,cookie,interval=1):
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}/drills/completion"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": cookie,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.post(url, headers=headers)
    if response.status_code == 500 :
        print("Server Error => probably try to read varitions")
        variations = getVariations(uuid,cookie)
        if variations  :
            print(f"reading variations(found={len(variations)})...")
            for var in variations :
                time.sleep(interval)
                readLesson(var,cookie)
        else :
            print("Can't read variations => no a valid uuid")
            return
    print(f"UUID: {uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)


def getVariations(course_uuid,cookie):
    url = f"https://cag.chessly.com/beta/openings/courses/{course_uuid}/variations"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": cookie,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    json_data = None
    response = requests.get(url, headers=headers)
    # print(response.status_code)
    if response.status_code == 401:
        print("unauthorised 404")
        # exit()
        return False
    if response.status_code == 200:
        json_data = response.json()
    else:
        print(
            f"Failed to fetch variations. Status code: {response.status_code}")
        return False

    # json to uuids
    lesson_uuids = []
    for key in json_data:
        nested_dict = json_data[key]
        for lesson_id in nested_dict:
            lesson_uuids.extend(nested_dict[lesson_id])
    return lesson_uuids

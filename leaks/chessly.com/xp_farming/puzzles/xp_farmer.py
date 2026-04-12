# import all libraries
import requests
import json
import time

""" 
======================= README ===========================
Steps to make the xp_farmer works well : 
    1. create an account , or use an existant account
    2. enter email and password to get the cookies (you can send this file to claude or chatgpt to verift that its safe and doesn"r send info )
    3. put it in the variable below 'COOKIE'
    4. run the file to test
"""

# IMPORTANT :
# create a test account => use its credentiels (infos) in this file
COOKIE = "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775757980$j36$l0$h0;"
email = "eldoradogpt2025@gmail.com"  # email of test account
password = "JT1215060000"  # password of the test account


# extract cookie


def get_secure_cst_cookie(email, password):
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
        "Cookie": "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775757980$j36$l0$h0",
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
        return f"__Secure-cst={cst_cookie}"
    except requests.RequestException as e:
        print("Cant get cookie")
        exit()


COOKIE += get_secure_cst_cookie(email, password)

# function to get all courses available on the plateform , and get their uuids


def extractAllLessonsUUID():
    global COOKIE
    url = "https://cag.chessly.com/beta/openings/courses"

    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": COOKIE,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # Parse JSON response
        data = response.json()
        # Extract all UUIDs from the 'id' fields
        uuids = [item['id'] for item in data if 'id' in item]

    return uuids


# 3. this simulate that you read the lesson (bug : you can do it more than 5 times for the same lesson)
def xp_from_lesson_part_uuid(uuid):
    global COOKIE
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}/drills/completion"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": COOKIE,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.post(url, headers=headers)
    print(f"UUID: {uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)
    # if 5 points => re read the same lesson
    # points
    points = response.json()["points"]
    if points > 0 :
        print(f"Points > {points} ==> read again")
        time.sleep(2)
        xp_from_lesson_part_uuid(uuid)
    else :
        print("enough points ==> next lesson part")


# 4. function to get uuid of variations
# -> for each lesson/opening , extract all variations , andtheir uuid


def getVariations(course_uuid):
    url = f"https://cag.chessly.com/beta/openings/courses/{course_uuid}/variations"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": COOKIE,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    json_data = None
    response = requests.get(url, headers=headers)
    # print(response.status_code)
    if response.status_code == 401:
        print("unauthorised 404")
        exit()
    if response.status_code == 200:
        json_data = response.json()
    else:
        print(
            f"Failed to fetch variations. Status code: {response.status_code}")
        return

    # json to uuids
    lesson_uuids = []
    for key in json_data:
        nested_dict = json_data[key]
        for lesson_id in nested_dict:
            lesson_uuids.extend(nested_dict[lesson_id])
    return lesson_uuids


#### start process ###
# 1. get all available lessons
lessons = extractAllLessonsUUID()

# 2. for each lesson extract the parts uuid
for lessonUUID in lessons[::-1]:
    parts = getVariations(lessonUUID)
    # 3. for each variation , make it as read
    for variationUUID in parts:
        time.sleep(2.5)  # wait 2.5 seconds to not get banned
        xp_from_lesson_part_uuid(variationUUID)

    """
        NOTE : after reading each variation of a lesson automatically ,
        you can see in the terminal : 
            "Response Body: {"points":5,"challengePoints":0}
        that  means the 'chessly.com' system approoved that you read the lesson , and 
        5 points of xp are added to your account statics
        NOTE : you can repeat the times of reading for every single part/variation so you gain more xp
    """

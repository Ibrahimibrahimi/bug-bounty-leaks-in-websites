import random
import requests
import time
# extract cookie


def getCookies(email="eldoradogpt2025@gmail.com", password="JT1215060000"):
    # "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775757980$j36$l0$h0;"
    COOKIE = generate_ga_cookies(
        "PNQ0H99BWZ", 984846498,  9976260047, session_duration=9989, event_count=80)
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
        print("Cant get cookie")
        exit()


def getOpenningCourses():
    url = 'https://cag.chessly.com/beta/openings/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': getCookies(),
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


def getLegacyCourses():
    url = 'https://cag.chessly.com/beta/legacy/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': getCookies(),
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


def getProgressLesosns():
    url = 'https://cag.chessly.com/beta/progress/courses'
    headers = {
        'Host': 'cag.chessly.com',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://chessly.com/',
        'Origin': 'https://chessly.com',
        'Connection': 'keep-alive',
        'Cookie': getCookies(),
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


def readLesson(uuid, interval=1):
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}/drills/completion"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": getCookies(),
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.post(url, headers=headers)
    if response.status_code == 500:
        print("Server Error => probably try to read varitions")
        variations = getVariations(uuid)
        if variations:
            print(f"reading variations(found={len(variations)})...")
            for var in variations:
                time.sleep(interval)
                b = readLesson(var) 
        else:
            print("Can't read variations => no a valid uuid")
            return False
    print(f"UUID: {uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)


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
        "Cookie": getCookies(),
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
        return []

    # json to uuids
    lesson_uuids = []
    for key in json_data:
        nested_dict = json_data[key]
        for lesson_id in nested_dict:
            lesson_uuids.extend(nested_dict[lesson_id])
    return lesson_uuids


# count all variations for all lessons
def countAllLessonsVariations():
    allCourses = getLegacyCourses() + getOpenningCourses() + getProgressLesosns()
    count = 0
    for lesson in allCourses:
        vr = getVariations(lesson)
        if vr:
            count += len(vr)
    return count

import requests
import time
import random
from cookiess import generate_ga_cookies


BASE_HEADERS = {
    "Host": "cag.chessly.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "https://chessly.com/",
    "Origin": "https://chessly.com",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
}


class ChesslyClient:

    BASE_URL = "https://cag.chessly.com/beta"

    def __init__(self, email: str, password: str, interval: float = 1.0):
        self.email    = email
        self.password = password
        self.interval = interval
        self.cookie   = None
        self._login()

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _login(self):
        ga_cookie = "_ga=GA1.1.1543400676.1773361473; _ga_PNQ0H99BWZ=GS2.1.s1775923106$o9$g1$t1775925202$j41$l0$h0;" # generate_ga_cookies("PNQ0H99BWZ")
        response  = self._request("POST", "/login",
                                cookie=ga_cookie,
                                json={"email": self.email, "password": self.password})
        cst = response.cookies.get("__Secure-cst")
        if not cst:
            raise ValueError("Login failed: __Secure-cst cookie not found in response.")
        self.cookie = ga_cookie + f" __Secure-cst={cst};"
        print("[+] Login successful.")

    # ── Core request handler ──────────────────────────────────────────────────

    def _request(self, method: str, endpoint: str, cookie: str = None, **kwargs) -> requests.Response:
        headers = {
            **BASE_HEADERS,
            "Cookie": cookie or self.cookie,
        }
        if method == "POST" and "json" in kwargs:
            headers["Content-Type"] = "application/json"

        url      = self.BASE_URL + endpoint
        response = requests.request(method, url, headers=headers, **kwargs)

        if response.status_code == 401:
            print("[!] Session expired, re-logging in...")
            self._login()
            headers["Cookie"] = self.cookie
            response = requests.request(method, url, headers=headers, **kwargs)

        response.raise_for_status()
        return response

    # ── Course fetchers ───────────────────────────────────────────────────────

    def get_opening_courses(self) -> list[str]:
        data = self._request("GET", "/openings/courses").json()
        return [item["id"] for item in data]

    def get_legacy_courses(self) -> list[str]:
        data = self._request("GET", "/legacy/courses").json()
        return [item["id"] for item in data]

    def get_progress_courses(self) -> list[str]:
        data = self._request("GET", "/progress/courses").json()
        return [item["id"] for item in data]

    def get_all_courses(self) -> list[str]:
        opening  = self.get_opening_courses()
        legacy   = self.get_legacy_courses()
        progress = self.get_progress_courses()
        all_ids  = list(set(opening + legacy + progress))  # deduplicate
        print(f"[+] Total unique courses: {len(all_ids)}")
        return all_ids

    # ── Variations ────────────────────────────────────────────────────────────

    def get_variations(self, course_uuid: str) -> list[str] | None:
        try:
            response  = self._request("GET", f"/openings/courses/{course_uuid}/variations")
            json_data = response.json()
        except requests.HTTPError as e:
            print(f"[-] Failed to get variations for {course_uuid}: {e}")
            return None

        lesson_uuids = []
        for key in json_data:
            nested = json_data[key]
            for lesson_id in nested:
                lesson_uuids.extend(nested[lesson_id])
        return lesson_uuids

    def count_all_variations(self) -> int:
        all_courses = self.get_all_courses()
        count = 0
        for course in all_courses:
            variations = self.get_variations(course)
            if variations:
                count += len(variations)
        print(f"[+] Total variations: {count}")
        return count

    # ── Lesson reader ─────────────────────────────────────────────────────────

    def read_lesson(self, uuid: str, _depth: int = 0):
        if _depth > 5:
            print(f"[!] Max recursion depth reached for {uuid}, skipping.")
            return

        try:
            endpoint = f"/progress/openings/studies/variations/{uuid}/courses/completion"
            response = self._request("POST", endpoint)
            print(f"[+] UUID: {uuid} — Status: {response.status_code}")
            print(response.text)
            
            

        except requests.HTTPError as e:
            if e.response.status_code == 500:
                print(f"[!] Server error on {uuid}, trying variations...")
                variations = self.get_variations(uuid)
                if variations:
                    print(f"[+] Reading {len(variations)} variation(s)...")
                    for var in variations:
                        time.sleep(self.interval)
                        self.read_lesson(var, _depth=_depth + 1)
                else:
                    print(f"[-] No variations found for {uuid}, skipping.")
            else:
                print(f"[-] HTTP error on {uuid}: {e}")

    def read_all_lessons(self):
        all_courses = self.get_all_courses()
        print(f"[+] Reading {len(all_courses)} courses...")
        for i, course in enumerate(all_courses, 1):
            print(f"\n[{i}/{len(all_courses)}] Course: {course}")
            time.sleep(self.interval)
            self.read_lesson(course)


# ── Entry point ───────────────────────────────────────────────────────────────


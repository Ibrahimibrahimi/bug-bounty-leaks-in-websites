import requests
import time

# Define your course UUID here
course_uuid = "bdd25532-960a-4849-aa41-76284546610a"

# Function to fetch variations data
def fetch_variations(course_uuid):
    url = f"https://cag.chessly.com/beta/openings/courses/{course_uuid}/variations"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775751025$j43$l0$h0; __Secure-cst=kPbghwJjpcBShY83b6p_U3BCmiIvQSL30CozNcGqBlEM",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch variations. Status code: {response.status_code}")
        return None

# Function to extract lesson UUIDs from the JSON response
def extract_lesson_uuids(json_data):
    lesson_uuids = []
    for key in json_data:
        nested_dict = json_data[key]
        for lesson_id in nested_dict:
            lesson_uuids.extend(nested_dict[lesson_id])
    return lesson_uuids

# Function to send a request for each lesson UUID
def process_lesson_uuid(lesson_uuid):
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{lesson_uuid}/drills/completion"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775749597$j13$l0$h0; __Secure-cst=kPbghwJjpcBShY83b6p_U3BCmiIvQSL30CozNcGqBlEM",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.post(url, headers=headers)
    print(f"Lesson UUID: {lesson_uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)

# Main execution
json_data = fetch_variations(course_uuid)
if json_data:
    lesson_uuids = extract_lesson_uuids(json_data)
    for uuid in lesson_uuids:
        process_lesson_uuid(uuid)
        time.sleep(0.7)
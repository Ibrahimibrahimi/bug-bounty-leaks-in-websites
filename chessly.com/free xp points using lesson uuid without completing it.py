import requests
import sys
import argparse

# Set up argument parser
parser = argparse.ArgumentParser(description='Send request with lesson UUID.')
parser.add_argument('--uuid', type=str, help='Lesson UUID')
args = parser.parse_args()

# Get UUID from argument or prompt user
if args.uuid:
    lesson_uuid = args.uuid
else:
    lesson_uuid = input("Enter lesson UUID: ")

# Construct the URL with the provided UUID
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

print("Status Code:", response.status_code)
print("Response Body:", response.text)
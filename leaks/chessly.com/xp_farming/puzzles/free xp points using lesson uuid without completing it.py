import requests
import sys
import argparse
import time

# Set up argument parser
parser = argparse.ArgumentParser(description='Send request with lesson UUID.')
parser.add_argument('--uuid', type=str, help='Lesson UUID')
parser.add_argument('--wordlist', type=str, help='Path to a file containing list of UUIDs')
args = parser.parse_args()

# Function to send request for a single UUID
def send_request(uuid):
    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}/drills/completion"
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
    print(f"UUID: {uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)

# Check which method to use
if args.uuid:
    # Single UUID provided
    send_request(args.uuid)
elif args.wordlist:
    # Read UUIDs from wordlist file and process each
    with open(args.wordlist, 'r') as file:
        uuids = [line.strip() for line in file if line.strip()]
    for uuid in uuids:
        send_request(uuid)
        time.sleep(0.7)
else:
    # Prompt user for UUID
    lesson_uuid = input("Enter lesson UUID: ")
    send_request(lesson_uuid)
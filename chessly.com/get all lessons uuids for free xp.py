import requests
import json

url = "https://cag.chessly.com/beta/openings/courses"

headers = {
    "Host": "cag.chessly.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "https://chessly.com/",
    "Origin": "https://chessly.com",
    "Connection": "keep-alive",
    "Cookie": "_ga=GA1.1.984846494.1775748892; _ga_PNQ0H99BWZ=GS2.1.s1775748891$o1$g1$t1775750183$j57$l0$h0; __Secure-cst=kPbghwJjpcBShY83b6p_U3BCmiIvQSL30CozNcGqBlEM",
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
    
    # Save UUIDs to a file
    with open("uuids.txt", "w") as file:
        for uuid in uuids:
            file.write(uuid + "\n")
    
    print(f"Extracted {len(uuids)} UUIDs and saved to 'uuids.txt'.")
else:
    print(f"Request failed with status code {response.status_code}")
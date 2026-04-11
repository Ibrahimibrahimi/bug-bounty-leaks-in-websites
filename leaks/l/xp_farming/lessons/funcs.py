
# get chapters of a course :
# https://cag.chessly.com/beta/openings/courses/

"""
Example of reponse : 
1) get reponse {"196d9fbe-f136-47f6-8ecb-d6b6703b9a86":{"702bdf06-d540-4a8c-9e15-881f8fe4782e":["0879017d-fc59-4fd7-a8fe-37c7aeba077d","e5a1f9da-4a0a-4c71-bccb-6e77db660a64","00c3c13a-edec-4749-a068-d9d9fe18059f","1416173a-6d43-4caf-b448-60482b8c12a2","e012a5bd-0a80-4b3c-9a65-ef0a74657cf4","661a495b-4ffd-4e32-a00d-8f43ee82be88","a0c651b5-f83b-4fbf-a29f-27ea9c5694c8","30d7a635-97df-4903-9ec0-d8210d3fc767"]},"28f029cd-1acb-4885-b33b-96fff81ea97a":{"502e8622-178f-41b4-86b3-34558a8c3b5d":["e9941526-d7c3-4ebc-8fb3-3c873e3ac20b","4b882a9d-4d68-4142-b21c-9cc4120cae37","8c0f22ba-4bc6-40da-9ea8-b8dc2a9a102b","59bdb434-425a-4fcf-b53f-50dd3342a74d"],"b3b919cf-8cb3-4c93-a10f-f4720c0d8ef2":["86820e44-401e-43e8-80d6-14128d8b11e9","ae3e6a0b-33ca-4f43-b81b-ddf4340a9cdb","e4ee8d80-6228-45c0-a2b2-d28c787f05e0","2669aba5-0b77-43be-82b4-05545f3a5c09","ad101327-d61f-46d9-806d-5b56fa982559"]},"39ec6fc0-3f96-4544-956f-7faf9cc741b1":{"7fc43b70-f932-4141-9a1f-9d6989e2f63f":["9211e5b0-a485-479e-95f9-ea0cf6327f73","4f8ae048-f75f-4ac6-ad06-74a8921adcfd","93b35cde-443f-4232-876c-8b61efc254be","63f490ef-d9c1-4014-999f-104cecbe7383","6bd3ed27-d666-496c-92dd-590cfdbc4622","ae9f32a6-b18c-45fd-8726-4d61a9ac5c5d","e0cafe0b-04ff-4057-93b5-4483454e8d0d"]},"499c7c16-852c-45c2-934c-99f0d4deb159":{"3f88b34d-8f9f-4d99-be74-14d8a8ef394c":["b2c189ef-6957-414f-b449-702ba65990d0","e5b64ae1-b16a-465c-89c6-76560a1db035","946cf9d8-ba80-4c6b-8356-4b73924ad9ea","921926d1-6ed2-42b8-b4da-534b83068dca","fa01a5d4-434d-4975-9061-828f7a11e0d8","41e1ead7-0aea-480e-b7fb-519e9447bfbf","0d78df4f-5633-4911-a015-481a565994a2","16c0be44-2c81-4689-baa2-9cfa093c17be","f4cccb07-160b-403e-8c88-5c2cef00f055","c53a8af4-1400-4e72-b7ff-7067f7f9fcb9"],"40d680f9-58c8-4369-bf08-fb35d96af8de":["23f5b6ed-40dc-4fe8-97a1-e221f9076d6d","3d15e498-5973-4c9d-a9a1-65251f82cd1a","d696355d-67ed-4f89-a1d6-ea476efdbf5c","2215b6f3-f6e3-4215-bd15-13afcbd9d8a8","5ff6a2a2-0ac4-4022-92f6-1a09efa3c5ee","11e7c423-4870-4764-8de3-32acd9ad2aea","3b4b5c87-51dd-4330-9347-b304c91c6515"]},"929b1b35-4701-47f4-902c-7ae7fa8c5235":{"414835dc-60c0-44da-a63a-cd5f4d4bfeae":["c8a15f20-ef39-4117-b222-03ac5f838ec3","29c1583f-341b-4f58-89e7-00f399eccfdf","00ffa157-49dd-4a73-8c8f-56c93acd0ec1","274c293b-f0c8-48b3-8db9-4d6b02cad0ba","c462acc2-3696-4cbc-bf8c-5be7f227a553"]},"d263613f-e7ee-43ee-beef-a7177421d52a":{"1bd81b7c-9112-478b-9a2e-14bcdf8a9856":["521639a3-7dc6-457f-9fb0-d6919b6a1a19","3dbf4e84-8a39-40fe-afcc-8b59ba6a1bfd","c321e715-a9cd-4615-87d4-3645b3cd83da","77b23dfe-c7c4-454c-a593-466a282007ac"]}}
2) use : 
def extract_all_uuids(data):
    uuids = []
    for key, value in data.items():
        for sub_key, uuid_list in value.items():
            uuids.extend(uuid_list)
    return uuids
to extract all uuids
"""

# read a course

import requests


def getVariations(uuid):
    url = f"https://cag.chessly.com/beta/openings/courses/{uuid}/variations"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga_PNQ0H99BWZ=GS2.1.s1775932600$o1$g1$t1775932691$j49$l0$h0; _ga=GA1.1.1881958528.1775932601; __Secure-cst=8qYGWQyYelB3LFTqHOfVyNTXjX0ULn3iOrTsmLSAzBse",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }
    response = requests.get(url, headers=headers)
    return response.json()


def extract_all_uuids(data):
    uuids = []
    for key, value in data.items():
        for sub_key, uuid_list in value.items():
            uuids.extend(uuid_list)
    return uuids


def extractAllLessonsUUID():
    url = "https://cag.chessly.com/beta/openings/courses"

    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga_PNQ0H99BWZ=GS2.1.s1775932600$o1$g1$t1775932691$j49$l0$h0; _ga=GA1.1.1881958528.1775932601; __Secure-cst=8qYGWQyYelB3LFTqHOfVyNTXjX0ULn3iOrTsmLSAzBse",
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


def xp_from_lesson_part_uuid(uuid):

    url = f"https://cag.chessly.com/beta/progress/openings/studies/variations/{uuid}/drills/completion"
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga_PNQ0H99BWZ=GS2.1.s1775932600$o1$g1$t1775932691$j49$l0$h0; _ga=GA1.1.1881958528.1775932601; __Secure-cst=8qYGWQyYelB3LFTqHOfVyNTXjX0ULn3iOrTsmLSAzBse",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
    }
    response = requests.post(url, headers=headers)
    print(f"UUID: {uuid} - Status Code: {response.status_code}")
    print("Response Body:", response.text)


def xp_from_video_uuid(uuid: str):
    url = f"https://cag.chessly.com/beta/progress/openings/videos/{uuid}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        # Add cookies if necessary
        "Cookie": "_ga_PNQ0H99BWZ=GS2.1.s1775932600$o1$g1$t1775932691$j49$l0$h0; _ga=GA1.1.1881958528.1775932601; __Secure-cst=8qYGWQyYelB3LFTqHOfVyNTXjX0ULn3iOrTsmLSAzBse",
    }

    response = requests.post(url, headers=headers)

    print("Status Code:", response.status_code)
    print("Response Body:", response.text)


xp_from_video_uuid("1d44f3cc-2db6-47c2-a7c3-3030458355eb")

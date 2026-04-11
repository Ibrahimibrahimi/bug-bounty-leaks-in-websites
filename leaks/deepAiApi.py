import requests
import json


def getDeepAiAnswer(query: str):
    url = "https://api.deepai.org/hacking_is_a_serious_crime"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "api-key": "tryit-29313838055-92efd3f13305fd73765982f1e4bd8c0b",
        "Origin": "https://deepai.org",
        "Connection": "keep-alive"
    }

    # Use `files` to simulate multipart/form-data
    files = {
        "chat_style": (None, "chat"),
        "chatHistory": (None, '[{"role":"user","content":"hi ,%s "}]' % query),
        "model": (None, "standard"),
        "session_uuid": (None, "bb3d57a9-405f-40e9-a6dc-0a831175d7b4"),
        "hacker_is_stinky": (None, "very_stinky"),
        "enabled_tools": (None, '["image_generator","image_editor"]')
    }

    response = requests.post(url, headers=headers, files=files)
    return response.text


print(getDeepAiAnswer("hi how are you"))

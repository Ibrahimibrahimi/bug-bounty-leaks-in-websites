def clean(text: str, replacements: dict) -> str:
    """Apply multiple string replacements to the given text."""
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def getModelAnswer(query: str = "hi", randomiseToken: bool = False) -> str:
    import requests
    import uuid

    # Endpoint
    url = "https://talkai.info/chat/send/"

    # Constants
    MODEL_OUTPUT = "event: trylimit 29An internal server error occurred."

    # Generate random UUID if needed
    random_uuid = uuid.uuid4()

    # Replacement rules
    replacements = {
        "\ndata:": "",
        "\n": "",
        MODEL_OUTPUT: "",
        "event": "\n",
        "trylimit": "\n\n  + trylimit :",
        "An internal server error occurred.": "",
        ": botmodel GPT 4.1 nano ": ""
    }

    # Tokens
    TOKEN_TEXT = "front=983159c1a0d70d635ba222039dfcf1ebb28830de2fe603511ad03b282cd997faa%3A2%3A%7Bi%3A0%3Bs%3A11%3A%22_csrf-front%22%3Bi%3A1%3Bs%3A32%3A%22i27T4lOZk9kL6-A3jXGqZyvitsv5E5V2%22%3B%7D"
    TOKEN = random_uuid if randomiseToken else TOKEN_TEXT
    CSRF_TOKEN = "983159c1a0d70d635ba222039dfcf1ebb28830de2fe603511ad03b282cd997faa%3A2%3A%7Bi%3A0%3Bs%3A11%3A%22_csrf-front%22%3Bi%3A1%3Bs%3A32%3A%22i27T4lOZk9kL6-A3jXGqZyvitsv5E5V2%22%3B%7D"

    # Headers
    headers = {
        "Host": "talkai.info",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "application/json, text/event-stream",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://talkai.info/chat/",
        "Content-Type": "application/json",
        "Origin": "https://talkai.info",
        "Connection": "keep-alive"
    }

    # Cookies (⚠️ Use valid ones)
    cookies = {
        "talkai-front": TOKEN,
        "_csrf-front": CSRF_TOKEN
    }

    # Request payload
    payload = {
        "type": "chat",
        "messagesHistory": [
            {
                "id": "11c594c7-ef6a-4bd3-b551-a0fb4f3b781e",
                "from": "you",
                "content": query,
                "model": "gpt-4.1-nano"
            }
        ],
        "settings": {
            "model": "gpt-4.1-nano",
            "temperature": 0.7
        }
    }

    # Send request
    response = requests.post(
        url,
        headers=headers,
        cookies=cookies,
        json=payload
    )

    # Process response
    model_answer = clean(response.text, replacements)
    return model_answer


# Example usage
if __name__ == "__main__":
    print(getModelAnswer("hi how are you"))

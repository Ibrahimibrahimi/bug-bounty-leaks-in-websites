# bug-bounty-leaks-in-websites



in this repository , i put all bugs i found in all websites


-------------------
## 1. free api for chatbot model
- website : `https://talkai.info/chat/`
- trick : use zaproxy to intercept the send message request and replace the token_front with a rtandom string (because the system doesn't check its validity)
- code : freemodel.py

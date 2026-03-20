# bug-bounty-leaks-in-websites



in this repository , i put all bugs i found in all websites


-------------------
## 1. free api for chatbot model : found trick
- website : `https://talkai.info/chat/`
- trick : use zaproxy to intercept the send message request and replace the token_front with a rtandom string (because the system doesn't check its validity)
- code : [talkAi.py](https://github.com/Ibrahimibrahimi/bug-bounty-leaks-in-websites/blob/main/talkAiAPI.py)
## 2. another **free api model** found by intercepting requests
- website : `https://api.deepai.org/`
- trick : use zaproxy to intercept the send message request and replace the token_front with a rtandom string (because the system doesn't check its validity)
- code : [deepAiApi.py](https://github.com/Ibrahimibrahimi/bug-bounty-leaks-in-websites/blob/main/deepAiApi.py)
## 3. Sensitive directories at **chari.com**
- the website is made by phpmyadmin
- leaks & access public for folders like chari.com/mysql ... 
- results : [leaks.txt](https://github.com/Ibrahimibrahimi/bug-bounty-leaks-in-websites/blob/main/chari.com-results.txt)

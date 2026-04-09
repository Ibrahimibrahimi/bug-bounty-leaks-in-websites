from faker import Faker
import asyncio
import aiohttp
import faker

url = "https://cag.chessly.com/beta/signup"


# Initialize the Faker object
fake = Faker()
emails = [fake.name() for i in range(5)]  # try less to test , more to use


async def create_account(session, email, psw="JT1215060000"):
    headers = {
        "Host": "cag.chessly.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://chessly.com/",
        "Content-Type": "application/json",
        "Origin": "https://chessly.com",
        "Connection": "keep-alive",
        "Cookie": "_ga=GA1.1.674526039.1775739200; _ga_PNQ0H99BWZ=GS2.1.s1775739200$o1$g1$t1775744776$j40$l0$h0; __Secure-cst=1CYyAscIQpOraReOULOX3s_KFiIxCvHH2CY2x6DGccVG",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site"
    }

    body = {
        "email": f"{email.replace(' ','')}@gmail.com",
        "password": psw
    }

    try:
        async with session.post(url, headers=headers, json=body) as response:
            text = await response.text()
            status = response.status
            print(status)
            if status == 204:
                return f"\nusername : {email}  | password : {psw}"
            if status == 429:  # baned
                print("BANED FROM WEBSITE")
                return
            if "error" in text:
                print(f"ERROR : {email} ==> {text}")
    except Exception as e:
        print(f"Exception for {email}: {e}")
    return ""


async def create_accounts_concurrently(emails, psw="JT1215060000"):
    async with aiohttp.ClientSession() as session:
        tasks = [create_account(session, email, psw) for email in emails]
        results = await asyncio.gather(*tasks)
    return "\n".join([res for res in results if res])


# Run the async function
log = asyncio.run(create_accounts_concurrently(emails))
with open("users from chessly.com.txt", "w") as file:
    file.write(log)

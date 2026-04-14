from tools import *


cookies = getCookies()



# exrtact all gotham bot uuids
bot_uuids = [str(uuid.uuid4()) for i in range(50)]

for bot_game in bot_uuids :
    win_bot_game(bot_game,cookies)
    time.sleep(2)
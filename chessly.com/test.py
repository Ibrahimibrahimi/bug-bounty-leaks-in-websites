from xp_farmer import xp_from_lesson_part_uuid


xp_from_lesson_part_uuid("87b2d106-d8f9-415c-841f-7e193baec75b")



# get lesson variations
def getVariations(lession_uuid) :
    url = f"https://cag.chessly.com/beta/openings/courses/{lession_uuid}/chapters"
    

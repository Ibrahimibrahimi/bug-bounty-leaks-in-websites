
from funcs import *

all_openings = get_openings_courses()
"""
time.sleep(1)  # intervall
for course in all_openings :
    chapters = extract_chapter_from_course(course)
    print("course : ",course , " chapters(",len(chapters),")")
    time.sleep(2)

    # extract chapters :
    for chapter in chapters :
        print("\t chapter : ",chapter)"""
for var in extract_variation_from_study("ced87143-df87-4aaf-9e5f-b2f25342cb7f"):
    readVariation(var)
    time.sleep(2)
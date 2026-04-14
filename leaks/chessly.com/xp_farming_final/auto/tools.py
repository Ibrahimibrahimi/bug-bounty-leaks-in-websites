
from funcs import *

def get_all_variations_uuids():
    # get all course
    all_openings = get_openings_courses()

    time.sleep(1)  # intervall
    all_uuids = [] 

    # for each course , extract chapters
    for course in all_openings:

        chapters = extract_chapter_from_course(course)
        time.sleep(2)  # interval
        # output
        print("      found : ", len(chapters), " chapters from ")

        # for each chapter , extract studies
        for chapter in chapters:
            studies = extract_study_from_chapter(chapter)
            time.sleep(2)
            print("              found ", len(studies), " studies ")
            # for each study , extract variations
            for study in studies:
                variations = extract_variation_from_study(study)
                time.sleep(2)
                print("                   found : ",
                    len(variations), " variations ")

                # for each variation => read it
                for var in variations:
                    all_uuids.append(var)
                    
    return all_uuids

from funcs import getOpenningCourses, getCookies, getLegacyCourses, getProgressLesosns, readLesson
import time

cookies = getCookies()

# extract all lessons
opLessons = getOpenningCourses(cookies)
LegacyLessons = getLegacyCourses(cookies)
progessLessons = getProgressLesosns(cookies)

# group all of them
allLessons = opLessons + LegacyLessons + progessLessons


# start reading
for lesson in range(len(allLessons)):
    print(f"============= [{lesson}] ==========")
    readLesson(allLessons[lesson])
    time.sleep(1)
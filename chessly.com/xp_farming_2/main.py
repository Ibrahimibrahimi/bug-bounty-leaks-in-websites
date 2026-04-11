from funcs import getOpenningCourses, getCookies, getLegacyCourses, getProgressLesosns, readLesson


cookies = getCookies()

# extract all lessons
opLessons = getOpenningCourses(cookies)
LegacyLessons = getLegacyCourses(cookies)
progessLessons = getProgressLesosns(cookies)

# group all of them
allLessons = opLessons + LegacyLessons + progessLessons


# start reading
readLesson(allLessons[0], cookies)
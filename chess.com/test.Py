

uuids = []

while True :
	i = input(f"uuid [{len(uuids)} found] : ")
	uuids.append(i)
	
	with open("saved uuids.txt","w") as file :
		file.writelines(uuids)

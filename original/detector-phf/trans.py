import sys

table = []
link = []
with open(sys.argv[1], 'r', encoding='UTF-8') as f:
	for x in  f.readlines():
		if("->" in x):
			y = x.split("->",1)
			dic = {}
			dic["source"] = y[0].strip()
			dic["target"] = y[1].split("[")[0].strip()
			dic["name"] = y[1].split("\"")[1].strip()
			# print(dic)
			link.append(dic)
		elif("table" in x):
			y = x.split("}\"")[0].split("|")
			dic = {}
			dic["name"] = y[0][:y[0].index(" ")]
			processorfilename = y[0][y[0].index("<head>")+6:] 
			dic[processorfilename.split(":", 1)[0].strip(" \"];")] = processorfilename.split(":", 1)[1].strip(" \"];")
			dic["label"] = []
			for item in y[1:]:
				if("label: " in item):
					dic["label"].append(item.split(":", 1)[1].strip(" \"];"))
				else:
					dic[item.split(":", 1)[0].strip(" \"];")] = item.split(":", 1)[1].strip(" \"];")
			# print(dic)
			table.append(dic)
	f.close()
with open(sys.argv[1].split(".dot")[0]+".txt", 'w', encoding='UTF-8') as f:
	f.write(str(table))
	# for item in table:
	f.write("\nvar links = ")
	f.write(str(link))

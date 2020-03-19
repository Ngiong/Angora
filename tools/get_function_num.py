import os

if not os.path.isdir('../queue'):
  print("This python script assumed to be in rels directory")
  exit()

num_of_tc = len([name for name in os.listdir('../queue') if os.path.isfile("../queue/" + name)])

sumn = 0
for i in range(4):
  relf = open("rel_all_" + str(i) + ".csv", "r")
  relf.readline()
  relf.readline()
  for line in relf:
    nums = line.split(",")[1:-1]
    for n in nums:
      sumn += int(n)
  relf.close()

print("# of TC : " + str(num_of_tc))
print("Total sum : " + str(sumn))
print("Avg # of uniq function call for each TC : " + str((sumn / num_of_tc) ** 0.5))

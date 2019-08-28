import sys

if len(sys.argv) < 2:
  print("python3 offset_size.py cond_queue.csv")
  exit()

f = open(sys.argv[1])
f.readline()

dicts = [dict(), dict(), dict(), dict()]
offsets = ["Offset",  "OffsetFunc", "OffsetRelFunc", "OffsetAllEnd"]
num = [0, 0, 0, 0]


for line in f:
  offset = line.strip().split(", ")[10]
  state = line.strip().split(", ")[11]
  
  offsetsize = 0
  if '&' in offset:
    offtmp = offset.split("&")
    for ttmp in offtmp:
      tttmp = ttmp.split("-")
      offsetsize += int(tttmp[1]) - int(tttmp[0])
  elif '-' in offset:
    tttmp = ttmp.split("-")
    offsetsize += int(tttmp[1]) - int( tttmp[0])
  
  try:
    stateidx = offsets.index(state)
  except:
    continue

  num[stateidx] += 1
  if offsetsize in dicts[stateidx]:
    dicts[stateidx][offsetsize] += 1
  else:
    dicts[stateidx][offsetsize] = 1
    

print (offsets)
print (num)
for i, dic in enumerate(dicts):
  offsetsize = 0
  for size in dic:
    offsetsize += size * dic[size]
  offsetsize /= num[i]
  print("%2f" % offsetsize, end = " ")
print("")


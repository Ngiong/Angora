import sys

if len(sys.argv) != 2:
    print("usage : python3 shirnk_rel.py rel_file.csv")
    exit(0)

relf = open(sys.argv[1], "r")
outf = open(".".join(sys.argv[1].split(".")[:-1]) + "_shrinked.csv", "w")

relf.readline()

func_rel = dict()
zeroed = set()
num_func = 0
for line in relf:
    zero = True
    rels = line.strip().split(",") [1:-1]
    for num in rels:
        if int(num) != 0:
            zero = False
            break 
    if zero :
        zeroed.add(num_func)
    else :
        func_rel[num_func] = rels
    num_func += 1

outf.write(",")
for idx in range(num_func):
    if idx in func_rel:
        outf.write(str(idx) + ",")
        rel = func_rel[idx]
        new_rel = []
        for idx2 in range(num_func):
            if idx2 not in zeroed:
                new_rel.append(rel[idx2])
        func_rel[idx] = new_rel

outf.write("\n")

for idx in range(num_func):
    if idx in func_rel:
        outf.write(str(idx) + ",")
        for rel in func_rel[idx]:
            outf.write(str(rel) + ",")
        outf.write("\n")

print("zeroed : " + str(len(zeroed)))
print("num_func : " + str(num_func))
relf.close()
outf.close()
import random

inp = open("md5all.txt", "r")

idx = 0
out = open("md5_" + str(idx) + ".txt", "w")
for l in inp:
  out.write(l)
  if random.random() < 1 / 130:
    out.close()
    idx += 1
    out = open ("md5_" + str(idx) + ".txt", "w")

out.close()
inp.close()

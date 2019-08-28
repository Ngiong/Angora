import sys
import subprocess

if len(sys.argv) != 5:
  print("python3 get_branch.py angora.csv \"executable_with_ar\" gcov_list.txt out.txt")

def progressBar(value, endvalue, bar_length=50):
  percent = float(value) / endvalue
  arrow = '■' * int(round(percent * bar_length))
  spaces = ' ' * (bar_length - len(arrow))
  sys.stdout.write("\rCalculating branch cov: [{0}] {1}%".format(arrow + spaces, int(round(percent * 100))))
  sys.stdout.flush()

num_lines = sum(1 for line in open(sys.argv[1]))

csvf = open(sys.argv[1], "r")
q_path = sys.argv[1][:-10] + "queue/"
gcovf = open(sys.argv[3], "r")
gcovfiles = gcovf.readlines()
gcovf.close()
outf = open(sys.argv[4], "w")
outf.write("sec,branch\n")

cmdline = ["find", "/home/cheong/fuzz_subjects/binutils-2.32-gcov/", "-name", "*.gcda", "-exec", "rm", "-f", "{}", ";"]
subprocess.run(cmdline)

prevtcs = 0 
csvf.readline()
lineidx = 0
for line in csvf: 
  if lineidx % 10 == 0:
    progressBar(lineidx, num_lines )
    pass
  lineidx += 1
  line = line.strip().split(", ")
  time = int(line[0])
  tcs = int(line[2])
  for i in range(prevtcs , tcs):
    tc_name = q_path + "id:" + "0" * (6 - len(str(i))) + str(i)
    cmdline = ["timeout" , "0.5"] + sys.argv[2].split(" ") + [tc_name]
    subprocess.run(cmdline, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
  covered_branch = 0
  for gfile in gcovfiles:
    if gfile == "" :
      continue
    cmdline = ["gcov", "-b", gfile[:-1]]
    gout = subprocess.run(cmdline, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout
    for l in gout.split(b"\n"):
      if l[0:3] == b"Tak":
        percent = float(l.split(b"once:")[1].split(b"% ")[0].decode())
        total = int (l.strip().split(b"of ")[1].decode())
        covered_branch += int(percent * total / 100)
  outf.write(str(time) + "," + str(covered_branch) + "\n")
  prevtcs = tcs


outf.close()
csvf.close()

cmdline = ["find", "/home/cheong/Angora_func/tools/", "-name", "*.gcov", "-exec", "rm", "-f", "{}", ";"]
subprocess.run(cmdline)

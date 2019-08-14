import sys
import subprocess

if len(sys.argv) < 2:
  print("python3 get_bug.py outdir_path execut")
  exit();

execut = sys.argv[2]

outdir_path = sys.argv[1]
cmd = ["ls", outdir_path]
out = subprocess.check_output(cmd, universal_newlines=True)

f2 = open("tmplog2", "w")
for line in out.split("\n")[:-1]:
  line = "timeout 0.5 " + execut + " " + outdir_path + line + "\n"
  f2.write(line)

f2.close()

cmd = ["chmod" , "+x", "tmplog2"]
subprocess.run(cmd)
cmd = ["bash", "./tmplog2"]
out2 = subprocess.run(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout
bugs = set()
for l in out2.split(b"\n"):
  if l[0:3] != b'Suc':
    continue
  bugn = l.split(b" ")[3]
  bugs.add(int(bugn[:-1]))

cmd = ["rm" , "tmplog2"]
subprocess.run(cmd)
print(bugs)
print(len(bugs))

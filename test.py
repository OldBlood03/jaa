import random
import sys
import string
from time import sleep
import random

# Execute and Print
string = [i for i in "ssdaoisighjoijwdoijafhisuhoijaoidjaohgijijoijsdasijduehgiuhodajshdiuhsignjnuahuwhcdaoisighjoijwdoijafhisuhoijaoidjaohgijijoijsdasijduehgiuhodajshdiuhsignjnuahuwhc"]
for i in range(100):
    print(f"[{i}/100]", flush = True)
    random.shuffle(string)
    print(f"{"".join(string)}", flush = True)
    print(f"{i}",file=sys.stderr)
    sleep(0.1);

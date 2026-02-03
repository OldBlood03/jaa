import random
import sys
import string
from time import sleep

# Execute and Print
for i in range(100):
    print(f"[{i}/100]", flush = True)
    print(f"\nsomething\n", flush = True)
    print(f"{i}",file=sys.stderr)
    sleep(0.1);

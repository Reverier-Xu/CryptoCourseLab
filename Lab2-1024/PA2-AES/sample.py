from oracle import *
import sys

if len(sys.argv) < 2:
    print("Usage: python sample.py <filename>")
    sys.exit(-1)

f = open(sys.argv[1])
data = f.read()
f.close()

ctext = [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]

oracle_connect()

rc = oracle_send(ctext, 3)
print("Oracle returned: %d" % rc)

oracle_disconnect()

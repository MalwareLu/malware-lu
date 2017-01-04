#!/usr/bin/env python
# decrypt-hancitor.py
#                  _                          _
#  _ __ ___   __ _| |_      ____ _ _ __ ___  | |_   _
# | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ | | | | |
# | | | | | | (_| | |\ V  V / (_| | | |  __/_| | |_| |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|_|  \___(_)_|\__,_|

import base64
import sys

filename=sys.argv[1]
output=sys.argv[2]
bytes_to_read = 22528
pattern = "NICEWORK"

f = open(filename, 'r')
data = f.read()
offset = data.find(pattern) + len(pattern) + 4

f.close

b = data[offset:offset+bytes_to_read]
value=""
tmp=""

for i in range(len(b)):	

	tmp   = chr(ord(b[i]) + 3)
	value += chr(ord(tmp) ^ 0x14)

open(output, 'wb').write(base64.b64decode(value))

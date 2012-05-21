#!/usr/bin/env python
import sys

def decode(src):
    r = ""
    for c in src:
        c = ord(c)
        if  c < 0x61 or c > 0x7a :
            if c < 0x41 or c > 0x5a:
                r += chr(c)
                continue
            x = (( c - 0x41 ) % 0x1a) + 0x41
        else:
            x = ((c - 0x54) % 0x1a) + 0x61

        r += chr(x)
    return r

def main():
    if len(sys.argv) != 2:
            sys.exit(1)

    f = open(sys.argv[1], 'rb')

    f.seek(0x1ae88, 0)
    data = f.read(0x32f) 
    for d in data.split("\0"):
        if len(d) == 0:
            continue
        print "%s : %s" % (d, decode(d))

if __name__ == "__main__":
    main()

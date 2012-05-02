#!/usr/bin/python
import sys

def decode(data, key):
    ret = "";
    for i in range(0, len(data)):
        c = ord(data[i]) ^ ord(key[i % (len(key))])
        ret += chr(c)
    return ret

def main():
    if len(sys.argv) != 2:
            sys.exit(1)

    f = open(sys.argv[1], 'rb')
    f.seek(0x1e14c, 0)
    key = f.read(0xb)

    f.seek(0x1e114, 0)
    data = f.read(0x18)
    print "url1:", decode(data, key)

    f.seek(0x1e130, 0)
    data = f.read(0x18)
    print "url2:", decode(data, key)

if __name__ == "__main__":
    main()

#!/usr/bin/env python
# xtremerat_config.py
#                  _                          _       
#  _ __ ___   __ _| |_      ____ _ _ __ ___  | |_   _ 
# | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ | | | | |
# | | | | | | (_| | |\ V  V / (_| | | |  __/_| | |_| |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|_|  \___(_)_|\__,_|

import pefile, os, sys, argparse
from struct import pack, unpack

version = "0.1"
def_rat_version = "v3.5"

# need to be finish
st = {
    'v3.5' : {
        'port' : {'pos':0, 'len':4, 'format': 'unpack("<I",d)[0]' },
        'host' : {'pos':0x14, 'len':(0x50-0x14), 'format': 'd' },
        'name' : {'pos':0x1b4, 'len':(0x1c6-0x1b4), 'format': 'd' },
        'name2' : {'pos':0x1c6, 'len':(0x1db-0x1c6), 'format': 'd' },
        'num' : {'pos':0x1dc, 'len':4, 'format': 'unpack("<I",d)[0]' },
        # something between this 2
        'name3' : {'pos':0x1e2, 'len':(0x1f8-0x1e2), 'format': 'd' },
        'name4' : {'pos':0x1f8, 'len':(0x208-0x1f8), 'format': 'd' },
        # something between this 2
        'name5' : {'pos':0x216, 'len':(0x236-0x216), 'format': 'd' },
        # something between this 2
        'name6' : {'pos':0x23a, 'len':(0x250-0x23a), 'format': 'd' },
        'name7' : {'pos':0x250, 'len':(0x264-0x250), 'format': 'd' },
        'name8' : {'pos':0x264, 'len':(0x2b4-0x264), 'format': 'd' },
        # something between this 2
        'name9' : {'pos':0x2bc, 'len':(0x2cc-0x2bc), 'format': 'd' },
        # something between this 2
        'name10' : {'pos':0x2d4, 'len':(0x2fc-0x2d8), 'format': 'd' },
        # something between this 2
        'name11' : {'pos':0x300, 'len':(0x316-0x300), 'format': 'd' },
    }
}

def print_conf(conf, version):
    s = st[version]
    for k, v in s.iteritems():
       d = conf[v['pos']:v['pos']+v['len']]
       #print "%s (%x:%x): %s" % (k, v['pos'], v['len'], d.encode('hex')) 
       df = eval(v['format'])
       print "%s: %s" % (k, df)
        

def arc4(key, key_len, data):
    x = 0
    box = range(256)
    for i in range(256):
		x = (x + box[i] + ord(key[i % key_len])) % 256 
		box[i], box[x] = box[x], box[i]

    #print box
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)  

def extract_resource(filename):
    pe =  pefile.PE(filename)
    # Fetch the index of the resource directory entry containing the strings
    rt_idx = [
        entry.id for entry in 
        pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

    # Get the directory entry
    rt_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_idx]

    # For each of the entries (which will each contain a block of 16 strings)
    i = 0
    for entry in rt_directory.directory.entries:
        # Get the RVA of the string data and
        # size of the string data
        data_rva = entry.directory.entries[0].data.struct.OffsetToData
        size = entry.directory.entries[0].data.struct.Size
        #print 'Directory entry at RVA', hex(data_rva), 'of size', hex(size)

        # Retrieve the actual data and start processing the strings
        data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
        offset = 0
        if i == 2:
            return data
        i+=1

    return ''

def list_version():
    print "Xtreme RAT supported version:"
    for key, v in st.iteritems():
        if key == def_rat_version:
            print "\t%s (default)" % key
        else:
            print "\t%s" % key

def main():
    parser = argparse.ArgumentParser(description = "Malware.lu xtreme rat config extractor")
    parser.add_argument('--version', action='version', 
        version="%(prog)s version " + version)
    parser.add_argument('-V', '--rat-version', action="store", default=def_rat_version, 
        help="RAT version if you use decode option (default %s)" % def_rat_version)
    #parser.add_argument('-l', '--list-version', action='store_true',
    #    help="Print list of supported RAT version")
    parser.add_argument('-d', '--decode', action='store_true',
        help="Print the decoded structure (under dev)")
    parser.add_argument( dest="filename", 
        help="extreme RAT binary file")

    r = parser.parse_args() 

    data = extract_resource(r.filename)
    d = arc4("C\x00O\x00N\x00F\x00I\x00G", 6, data)
    
    if r.decode:
        print_conf(d, r.rat_version)
    else:
        sys.stdout.write(d)

if __name__ == '__main__':
    main()


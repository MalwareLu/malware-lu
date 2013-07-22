#!/usr/bin/env python
# cloger7_config.py
#                  _                          _       
#  _ __ ___   __ _| |_      ____ _ _ __ ___  | |_   _ 
# | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ | | | | |
# | | | | | | (_| | |\ V  V / (_| | | |  __/_| | |_| |
# |_| |_| |_|\__,_|_| \_/\_/ \__,_|_|  \___(_)_|\__,_|


import sys,argparse,re,base64



def print_conf(filename):
    malware = open(filename,"rb")
    
    clog = re.compile("@CLOG7@")
    parsed = []
    for line in malware:
        parsed= clog.split(line)
    
    result = {}
    
    #result["code"] = parsed[0]
    result["mail_host"] = parsed[1]
    result["mail_port"] = parsed[2]
    result["mail_adress"] = base64.b64decode(parsed[3])
    result["mail_pass"] = base64.b64decode(parsed[4])
    result["mail_adress2"] = base64.b64decode(parsed[5])
    result["ftp_adress"] = parsed[6]
    result["ftp_user"] = parsed[7]
    result["ftp_pass"] = parsed[8]
    result["temp_folder"] = parsed[9]
    result["disable_taskManager_enabled"] = parsed[10]
    result["unknown_option1"] = parsed[11]
    result["unknown_option2"] = parsed[12]
    result["unknown_option3"] = parsed[13]
    result["name_of_server"] = parsed[14]+".exe"
    result["addstartup_enabled"] = parsed[15]
    result["msgBoxStyle.information"] = parsed[16]
    result["msgBoxStyle.exclamation"] = parsed[17]
    result["msgBoxStyle.question"] = parsed[18]
    result["msgBoxStyle.critical"] = parsed[19]
    result["msgBox_message"] = parsed[20]
    result["msgBox_title"] = parsed[21]
    result["mutex"] = parsed[22]

    for key in result:
        print(key+" : "+result[key])


def main():
    parser = argparse.ArgumentParser(description = "Malware.lu CLoger7 config extractor")
    parser.add_argument('-d', '--decode', action='store_true',
        help="Print the configuration")
    parser.add_argument( dest="filename", 
        help="CLoger7 binary file")
    try:
        r = parser.parse_args()

        if r.decode:
            print_conf(r.filename)
        else:
            parser.print_help()
            
    except Exception as e:
        print >> sys.stderr, "Exception", e

if __name__ == '__main__':
    main()	
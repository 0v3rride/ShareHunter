#!/usr/bin/env python

from os import *;
from argparse import *;
from smb.SMBConnection import SMBConnection;
from socket import *;
from time import *;
import re;
import platform;
import io;


def getArgs():
    parser = ArgumentParser(description="Find accessible shares on the network.");
    group = parser.add_mutually_exclusive_group(required=True);
    group2 = parser.add_mutually_exclusive_group(required=False);
    group.add_argument("-host", help="IP address or fqdn of host you want to enumerate shares on.");
    group.add_argument("-hosts", help="Absolute path to file containing list of hosts to enumerate shares on. This can be a mix of IP addresses and or FQDNs.");
    parser.add_argument("-ports", required=False, nargs="+", type=int, default=(445, 139), help="Comma separated list of ports (Default: 445 and 139)");
    group2.add_argument("-lssubdirs", required=False, action="store_true", default=False, help="List all subdirectories in the share recursively (Default: false)");
    group2.add_argument("-lsfiles", required=False, action="store_true", default=False, help="List all files in the share recursively (Default: false)");
    parser.add_argument("-user", required=False, type=str, default=None, help="(Default: \"\")");
    parser.add_argument("-pword", required=False, type=str, default=None, help="(Default: \"\")");
    parser.add_argument("-wait", required=False, type=int, default=0, help="Wait time in-between enumeration of shares (Default: 0)");
    parser.add_argument("-domain", required=False, type=str, default="", help="Domain (Default: None)");
    parser.add_argument("-timeout", required=False, type=float, default=5, help="The amount of time sharehunter should spend trying to connect to a share before timing out (Default: 5 seconds. Also can take a float value like .5)");
    parser.add_argument("-keywordexp", required=False, type=str, default=None, help="Use with lsfiles or lssubdirs flags - Search for keywords in recursive listing (Default: None - use regular expressions to search for keywords - e.g. 'password|secret')")

    return parser.parse_args();


def getPermissions(unc):
    bitval = 0;

    try:
        if access(unc, R_OK):
            bitval += 4;
        if access(unc, W_OK):
            bitval += 2;

        return {
            0: "NO PERMS",
            2: "WRITE",
            4: "READ",
            6: "READ, WRITE",
        }.get(bitval, "UNKNOWN");
    except:
        return "ERROR: FPCNC";


def keywordSearch(keyword, path):
    if re.search(keyword, path, re.I) is not None:
        print(path);


def listAllFiles(sharepath, kwrdexp):
    for root, subdirs, files in walk(sharepath):
        for f in files:
            if kwrdexp and platform.system() is "Windows":
                keywordSearch(kwrdexp, "{}\{}".format(root, f));
            elif kwrdexp and platform.system():
                keywordSearch(kwrdexp, "{}/{}".format(root, f));
            elif platform.system() is "Windows":
                print("{}\{}".format(root, f));
            else:
                print("{}/{}".format(root, f));
    print("");


def listAllSubdirs(sharepath, kwrdexp):
    for root, subdirs, files in walk(sharepath):
        for s in subdirs:
            if kwrdexp and platform.system() is "Windows":
                keywordSearch(kwrdexp, "{}\{}".format(root, s));
            elif kwrdexp and platform.system():
                keywordSearch(kwrdexp, "{}/{}".format(root, s));
            elif platform.system() is "Windows":
                print("{}\{}".format(root, s));
            else:
                print("{}/{}".format(root, s));
    print("");


def hostsEnum(hostsFile, ports, user, pword, slptm, addomain, lssubdirs, tmout, lsfiles, kwdexp):
    try:
        with io.open(hostsFile, "r") as hosts:
            for host in hosts.read().splitlines():
                for port in ports:
                    try:
                        s = SMBConnection(username=user, password=pword, my_name=gethostname(), remote_name=host,
                                          domain=addomain, use_ntlm_v2=True,
                                          sign_options=SMBConnection.SIGN_WHEN_REQUIRED, is_direct_tcp=True);
                        s.connect(host, port, timeout=tmout);
                        sleep(slptm);

                        print("[i] MACHINE NAME: {}\n[i] IP ADDRESS: {}\n[i] PORT: {}\n[i] SHARE INFO:\n".format(getfqdn(host), host, port));

                        for share in s.listShares():
                            sharePath = path.join(r"\\", host, share.name);
                            print("[*] {} : {} : {}".format(getPermissions(sharePath), share.name, share.comments));

                            if lssubdirs:
                                print(r"RESURSIVE SUBDIRECTORY LISTINGS FOR SHARE: {}:".format(sharePath));
                                listAllSubdirs(sharePath, kwdexp);
                            elif lsfiles:
                                print(r"RECURSIVE FILE LISTINGS FOR SHARE: {}:".format(sharePath));
                                listAllFiles(sharePath, kwdexp);

                        print("{}".format("="*150));
                    except Exception as e:
                        print("!!!ERROR: {}:{} ({}) - {}\n{}\n".format(host, port, getfqdn(host), e, "="*150));
    except KeyboardInterrupt as ki:
        print("[!]: Script Aborted!");


def hostEnum(host, ports, user, pword, slptm, addomain, lssubdirs, tmout, lsfiles, kwdexp):
    try:
        for port in ports:
            try:
                s = SMBConnection(username=user, password=pword, my_name=gethostname(), remote_name=host,
                                  domain=addomain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_REQUIRED,
                                  is_direct_tcp=True);
                s.connect(host, port, timeout=tmout);
                sleep(slptm);

                print("[i] MACHINE NAME: {}\n[i] IP ADDRESS: {}\n[i] PORT: {}\n[i] SHARE INFO:\n".format(getfqdn(host), host, port));

                for share in s.listShares():
                    sharePath = path.join(r"\\", host, share.name);
                    print("[*] {} : {} : {}".format(getPermissions(sharePath), share.name, share.comments));

                    if lssubdirs:
                        print(r"RESURSIVE SUBDIRECTORY LISTINGS FOR SHARE: {}:".format(sharePath));
                        listAllSubdirs(sharePath, kwdexp);
                    elif lsfiles:
                        print(r"RECURSIVE FILE LISTINGS FOR SHARE: {}:".format(sharePath));
                        listAllFiles(sharePath, kwdexp);

                print("{}".format("="*150));
            except Exception as e:
                print("!!!ERROR: {}:{} ({}) - {}\n{}\n".format(host, port, getfqdn(host), e, "="*150));
    except KeyboardInterrupt as ki:
        print("[!]: Script Aborted!");


def parseArgs():
    args = getArgs();
    user = "";
    pword = "";

    # Check username argument-------------------------------------------
    if not args.user:
        user = input("Username to use to authenticate to shares: ");
    elif args.user:
        user = args.user;

    if not user or user is "":
        user = "";

    #Check password argument-------------------------------------------
    if not args.pword:
        pword = input("Password for username that will be used: ");
    elif args.pword:
        pword = args.pword;

    if not pword or pword is "":
        pword = "";

    if (args.host and not args.hosts):
        hostEnum(args.host, args.ports, user, pword, args.wait, args.domain, args.lssubdirs, args.timeout, args.lsfiles, args.keywordexp);
    elif (args.hosts and not args.host):
        hostsEnum(path.abspath(args.hosts), args.ports, user, pword, args.wait, args.domain, args.lssubdirs, args.timeout, args.lsfiles, args.keywordexp);


def main():
    print("""
                   _________________
                  /        ^        \\
                 /         |         \\
                /   /*****\|          \\
               /   +---------------+   \\
              /    |Top    |       |    \\
             /     |Secret +       |     \\
            |<------------+o+------------>|
             \     |       +       |     /
              \    |       |       |    /
               \   +---------------+   /
                \          |          /
                 \         |         /
                  \________v________/

 __             __   ___                   ___  ___  __  
/__` |__|  /\  |__) |__     |__| |  | |\ |  |  |__  |__) 
.__/ |  | /--\ |  \ |___    |  | \__/ | \|  |  |___ |  \ v0.5

            [*] https://github.com/0v3rride
            [*] Script has started...
            [*] Use CTRL+C to cancel the script at anytime.

    """);


    parseArgs();


# Begin
main();




# def spiderShares(sharepath, depth, tabcount):
#     try:
#         for item in listdir(sharepath):
#             print("{}{}{}".format("\t" * tabcount,"- ", str(item)));
#
#             # take current dir share, add dir to path and then list if depth is greater than 0
#
#             if depth is 1:
#                 try:
#                     tabcount += 1;
#                     if path.isdir("{}\\{}".format(sharepath, item)):
#                         for subitem in listdir("{}\\{}".format(sharepath, item)):
#                             print("{}{}{}".format("\t" * tabcount, "- ", str(subitem)));
#                     elif path.isfile("{}\\{}".format(sharepath, item)):
#                         print("{}{}{}".format("\t" * tabcount, "- ", str(item)));
#                 except Exception as se:
#                         print("!!!ERROR: {}".format(se));
#             tabcount = 0;
#
#     except Exception as le:
#         print("!!!ERROR: {}".format(le));
#
#     print("\n");

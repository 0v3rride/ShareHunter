#!/usr/bin/env python

from os import *;
from argparse import *;
from smb.SMBConnection import SMBConnection;
from socket import *;
from time import *;
import io;


def getArgs():
    parser = ArgumentParser(description="Find accessible shares on the network.");
    group = parser.add_mutually_exclusive_group(required=True);
    group.add_argument("-host", help="IP address or fqdn of host you want to enumerate shares on.");
    group.add_argument("-hosts", help="Absolute path to file containing list of hosts to enumerate shares on. This can be a mix of IP addresses and or FQDNs.");
    parser.add_argument("-ports", required=False, nargs="+", type=int, default=(445, 139), help="Ports (Default: 445 and 139)");
    parser.add_argument("-user", required=False, type=str, default=None, help="(Default: \"\")");
    parser.add_argument("-pword", required=False, type=str, default=None, help="(Default: \"\")");
    parser.add_argument("-wait", required=False, type=int, default=0, help="Wait time in-between enumeration of shares (Default: 0)");
    parser.add_argument("-domain", required=False, type=str, default="", help="Domain (Default: None)");
    parser.add_argument("-verbose", required=False, action="store_true", default=False, help="List files and directories in shares (Default: false)");

    return parser.parse_args();


def getPermissions(unc):
    bitval = 0;

    if access(unc, R_OK):
        bitval += 4;
    if access(unc, X_OK):
        bitval += 1;
    if access(unc, W_OK):
        bitval += 2;

    return {
        0: "---",
        1: "--x",
        2: "-w-",
        3: "-wx",
        4: "r--",
        5: "r-x",
        6: "rw-",
        7: "rwx"
    }.get(bitval, "---");


def getShareComments(comment):
    try:
        return " : {}".format(comment) if comment is not "" else "";
    except Exception as er:
        return "";


def enumShares(hostsFile, ports, user, pword, slptm, addomain, lsdir):
    try:
        with io.open(hostsFile, "r") as hosts:
            for host in hosts.read().splitlines():
                for port in ports:
                    try:
                        s = SMBConnection(user, pword, gethostname(), host, addomain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_REQUIRED, is_direct_tcp=True);
                        s.connect(host, port);
                        sleep(slptm);

                        print("[i] IP ADDRESS OR MACHINE NAME: {}\n[i] PORT: {}\n[i] SHARE INFO:\n".format(host, port));

                        for share in s.listShares():
                            print("{} : {}{}".format(getPermissions("\\\\{}\\{}".format(host, share.name)), share.name,
                                                     getShareComments(share.comments)));

                            if lsdir:
                                print("DIRECTORY LISTING FOR {}:".format(share.name));
                                try:
                                    for item in listdir("\\\\{}\\{}".format(host, share.name)):
                                        print("{}{}".format("   -", item));
                                except Exception as le:
                                    print("MESSAGE: {}".format(le));
                                print("\n");

                        print("\n");
                    except Exception as e:
                        print("MESSAGE: {}:{} - {}\n".format(host, port, e));
    except KeyboardInterrupt as ki:
        print("[!]: Script Aborted!");


def enumShare(host, ports, user, pword, slptm, addomain, lsdir):
    try:
        for port in ports:
            try:
                s = SMBConnection(user, pword, gethostname(), host, addomain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_REQUIRED, is_direct_tcp=True);
                s.connect(host, port);
                sleep(slptm);

                print("[i] IP ADDRESS OR MACHINE NAME: {}\n[i] PORT: {}\n[i] SHARE INFO:\n".format(host, port));

                for share in s.listShares():
                    print("{} : {}{}".format(getPermissions("\\\\{}\\{}".format(host, share.name)), share.name,
                                             getShareComments(share.comments)));

                    if lsdir:
                        print("DIRECTORY LISTING FOR {}:".format(share.name));
                        try:
                            for item in listdir("\\\\{}\\{}".format(host, share.name)):
                                print("{}{}".format("   -", item));
                        except Exception as le:
                            print("MESSAGE: {}".format(le));
                        print("\n");

                print("\n");
            except Exception as e:
                print("MESSAGE: {}:{} - {}\n".format(host, port, e));
    except KeyboardInterrupt as ki:
        print("[!]: Script Aborted!");


def parseArgs():
    args = getArgs();
    user = "";
    pword = "";

    if not args.user:
        user = input("Username to use to authenticate to shares: ");
    elif args.user:
        user = args.user;

    if not args.pword:
        pword = input("Password for username that will be used: ");
    elif args.pword:
        pword = args.pword;

    if (args.host and not args.hosts):
        enumShare(args.host, args.ports, str(user), str(pword), args.wait, args.domain, args.verbose);
    elif (args.hosts and not args.host):
        enumShares(path.abspath(args.hosts), args.ports, str(user), str(pword), args.wait, args.domain, args.verbose);


def main():
    print("""
 __             __   ___                   ___  ___  __  
/__` |__|  /\  |__) |__     |__| |  | |\ |  |  |__  |__) 
.__/ |  | /--\ |  \ |___    |  | \__/ | \|  |  |___ |  \ v0.2

            [*] https://github.com/0v3rride
            [*] Script has started...
            [*] Use CTRL+C to cancel the script at anytime.

    """);

    # Begin
    parseArgs();


# main
main();





# PREVIOUS WORKING VERSION VERSION

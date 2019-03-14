from os import *;
from argparse import *;
from smb.SMBConnection import SMBConnection;
from socket import *;
from time import *;
import io;


def getArgs():
    parser = ArgumentParser(description="Find accessible shares on the network.");
    parser.add_argument("-host", required=False, help="IP address or fqdn of host you want to enumerate shares on.");
    parser.add_argument("-hosts", required=False, help="Absolute path to file containing list of hosts to enumerate shares on. This can be a mix of IP addresses and or FQDNs.");
    parser.add_argument("-ports", required=False, nargs="+", type=int, default=(445,139), help="Ports (Default: 445 and 139)");
    parser.add_argument("-user", required=False, type=str, default="", help="(Default: \"\")");
    parser.add_argument("-pword", required=False, type=str, default="", help="(Default: \"\")");
    parser.add_argument("-wait", required=False, type=int, default=0, help="Wait time in-between enumeration of shares (Default: 0)");
    parser.add_argument("-domain", required=False, type=str, default=None, help="Domain (Default: None)");
    #parser.add_argument("-verbose", required=False, type=bool, action="store_false", default=False, help="Output file names in each share, etc.");

    return parser.parse_args();


def getPermissions(unc):
    bitval = 0;

    if access(unc, R_OK) is True:
        bitval += 4;
    if access(unc, X_OK) is True:
        bitval += 1;
    if access(unc, W_OK) is True:
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
    }.get(bitval,"---");


def getShareComments(comment):
    try:
        return " : {}".format(comment) if comment is not "" else "";
    except Exception as er:
        return "";


def enumShares(hostsFile, ports, user, pword, slptm, adDomain):
    with io.open(hostsFile, "r") as hosts:
        for host in hosts.read().splitlines():
            for port in ports:
                try:
                    s = SMBConnection(user, pword, gethostname(), host, adDomain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_REQUIRED, is_direct_tcp=True);
                    s.connect(host, port);
                    sleep(slptm);

                    print("IP Address/Machine Name: {}\nPort: {}\nShares:".format(host, port));

                    for share in s.listShares():
                        print("{} : {}{}".format(getPermissions("\\\\{}\\{}".format(host, share.name)), share.name, getShareComments(share.comments)));

                    print("\n");
                except Exception as e:
                    print("MESSAGE: {} - {}\n".format(host, e));


def enumShare(host, ports, user, pword, slptm, adDomain):
    for port in ports:
        try:
            s = SMBConnection(user, pword, gethostname(), host, adDomain, use_ntlm_v2=True, sign_options=SMBConnection.SIGN_WHEN_REQUIRED, is_direct_tcp=True);
            s.connect(host, port);
            sleep(slptm);

            print("IP Address/Machine Name: {}\nPort: {}\nShares:".format(host, port));

            for share in s.listShares():
                print("{} : {}{}".format(getPermissions("\\\\{}\\{}".format(host, share.name)), share.name, getShareComments(share.comments)));

            print("\n");
        except Exception as e:
            print("MESSAGE: {} - {}\n".format(host, e));


def parseArgs():
    args = getArgs();

    if(args.host and not args.hosts):
        enumShare(args.host, args.ports, args.user, args.pword, args.wait, args.domain);
    elif(args.hosts and not args.host):
        enumShares(path.abspath(args.hosts), args.ports, args.user, args.pword, args.wait, args.domain);
    else:
        print("[!]: Choose either -host or -hosts argument in a single instance!");


def main():
    print("""
 __             __   ___                   ___  ___  __  
/__` |__|  /\  |__) |__     |__| |  | |\ |  |  |__  |__) 
.__/ |  | /--\ |  \ |___    |  | \__/ | \|  |  |___ |  \ v0.1
     
            [*] https://github.com/0v3rride
            [*] Script has started...
            [*] Use CTRL+C to cancel the script at anytime.                                                         
    """);

    #Begin
    parseArgs();


#main
main();

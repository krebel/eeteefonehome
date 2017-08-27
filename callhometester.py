#!/usr/bin/python
#
# Script to test access to the AutoSupport CallHome systems.
#

from __future__ import print_function
import os, sys, commands, re, time, socket, fcntl, struct

now = time.strftime('%Y-%m-%d_%H-%M-%S')
log = open('/tmp/chtest_' + str(now) + '.log', 'a')

# Callhome/AutoSupport servers:
reg = "api.appliance.veritas.com"
telem = "telemetry.veritas.com"
rec = "receiver.appliance.veritas.com"

srchstrngs = (reg, telem, rec)
curlsvrs = (reg, telem)

# First check if basic DNS connectivity exists. If not, exit completely out w/warning/homework.
def dnsordie():
    for word in srchstrngs:
        diginfo = commands.getoutput('dig +time=1 +tries=1 +retry=1 ' + word)
        if 'no servers could be reached' in diginfo:
            print('A DNS server is either unconfigured or unreachable on this appliance. Please configure a working DNS server.')
            print('Note: Callhome/Autosupport servers use dynamic IP addresses that change frequently. DNS hostname resolution is required.' + '\n')
            exit()
        else:
            continue

def selfname():
    self = commands.getoutput('hostname')
    print ('\n' + 'OS hostname is: ' + self + '\n\n')
    log.write('OS hostname is: ' + self  + '\n\n')


def gethwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def printmac():
    mac = gethwaddr('eth0')
    print('1) MAC address for eth0 is: ' + mac + '\n\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('1) MAC address for eth0 is:' + mac + '\n\n')

def hostschk():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    hstsFile = open('/etc/hosts', 'r')
    for line in hstsFile:
        for word in srchstrngs:
            if word in line:
                print('2) ' + line, end='')
                print("Please remove all references to Callhome/Autosupport servers from the /etc/hosts file." + '\n')
                log.write('2' + line + '\n\n')
            else:
                print("2) callhome servers do not appear in /etc/hosts. (Good!)" + '\n\n')
                log.write("2) callhome servers do not appear in /etc/hosts. (Good!)" + "\n\n")
                return()
    hstsFile.close()


def resolve_chk():
    print('Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    for word in srchstrngs:
        digem = commands.getoutput('dig +noall +answer ' + word)
        print(digem)
        log.write(digem + '\n')
        log.write(' ' + '\n\n')
    print(' ' + '\n')

def resolv_chk():
    print('3) Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('3) Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    for word in srchstrngs:
        dignfo = commands.getoutput('dig ' + word)
        answrregex = re.compile(r'ANSWER: \d')
        hits = answrregex.search(dignfo)
        answrvalregex = re.compile(r'\d')
        answrval = answrvalregex.search(hits.group())
        if (hits.group()) == 'ANSWER: 0':
            print('DNS has no record of ' + word + '\n' + 'Please ensure the appliance can query DNS for all Callhome/Autosupport server records.')
        else:
            print('DNS resolved ' + word)
    print(' ' + '\n')



def ssl_ec2_test():
    appmonips = commands.getoutput('dig +short ' + reg)
    tmpF = open('/tmp/tmpfile.txt', 'a')
    tmpF.write(appmonips)
    tmpF.close()
    tmpF = open('/tmp/tmpfile.txt', 'r')
    for line in tmpF:
        reverseDig = commands.getoutput('dig +short -x ' + line.strip())
    print('4) Retrieving Certificate chain:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('4) Retrieving Certificate chain:' + '\n')
    log.write(' ' + '\n')
    sslchain = commands.getoutput('echo QUIT | openssl s_client -connect ' + reverseDig.rstrip('.') + ':443')
    log.write(sslchain + '\n\n')
    tmpF2= open('/tmp/tmpfile2.txt', 'w')
    tmpF2.write(sslchain)
    tmpF2.close()
    tmpF2= open('/tmp/tmpfile2.txt', 'r')
    for line in tmpF2:
        if re.search('s:|:i', line):
            print(line)
    print(' ' + '\n')
    tmpF2.close()


def ssl_yhoo_test():
    print('5) Retrieving www.yahoo.com Certificate chain:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('5) Retrieving www.yahoo.com Certificate chain:' + '\n\n')
    log.write(' ' + '\n\n')
    yahoosslchain = commands.getoutput('echo QUIT | openssl s_client -connect www.yahoo.com:443')
    log.write(yahoosslchain + '\n\n')
    tmpF2= open('/tmp/tmpfile2.txt', 'w')
    tmpF2.write(yahoosslchain)
    tmpF2.close()
    tmpF2= open('/tmp/tmpfile2.txt', 'r')
    for line in tmpF2:
        if re.search('s:|:i', line):
            print(line)
    print("Note: if we cannot connect to yahoo.com port 443, then there is definitely something on the network preventing it." + '\n\n')
    log.write("Note: if we cannot connect to yahoo.com port 443, then there is definitely something on the network preventing it." + '\n\n')
    tmpF2.close()

def curltest():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("6) Curl connection attempts:" + '\n')
    log.write("Curl connection attempts:" + "\n")
    for word in curlsvrs:
        curlem = commands.getoutput('curl --connect-timeout 30 -sL -w "%{http_code} (%{url_effective})\\n" http://' + word + ' -o /dev/null')
        print(curlem)
        log.write(curlem + '\n\n')
        log.write(' ' + '\n\n')
    print('Note: HTTP codes considered as normal: 200 = OK, 401 = Authorization Required, 403 = Forbidden' + '\n\n')
    print(' ' + '\n')

def w3mit():
    blnk = ''
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    w3mout = commands.getoutput('w3m -dump https://receiver.appliance.veritas.com')
    if w3mout == blnk:
        print("7) Appliance successfully connects directly to receiver.appliance.veritas.com" + '\n\n')
        log.write("7) Appliance successfully connects directly to receiver.appliance.veritas.com" + '\n\n')
    else:
        print("7) Appliance unable to connect directly to receiver.appliance.veritas.com...there may be a proxy server." + '\n\n')
        log.write("7) Appliance unable to connect directly to receiver.appliance.veritas.com...there may be a proxy server." + '\n\n')
        log.write(w3mout)
        log.write(' ' + '\n')


def trace():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write("8) Traceroute connection attempts:" + "\n\n")
    trc = commands.getoutput('traceroute -T receiver.appliance.veritas.com')
    log.write(trc)
    # TODO: read last hostname/ip in traceroute output before triple asterisk, that could be the proxy server


def get_chinfo():
    print('8) Gathering chinfo.txt and callhome_secret:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('9) Gathering chinfo.txt and callhome_secret:' + '\n\n')
    print('/usr/openv/runtime_data/chinfo.txt contains:' + '\n')
    if os.path.exists('/usr/openv/runtime_data/chinfo.txt'):
        chConf = open('/usr/openv/runtime_data/chinfo.txt', "r")
        chConfgutz = chConf.read()
        log.write('/usr/openv/runtime_data/chinfo.txt contains:' + '\n\n')
        log.write(chConfgutz + '\n\n')
        print(chConfgutz)
        chConf.close()
#except IOError:
    else:
        print ("----- Could not locate /usr/openv/runtime_data/chinfo.txt file - aborting" + '\n')
        log.write('----- Could not locate /usr/openv/runtime_data/chinfo.txt file - aborting' + '\n\n')


def get_callhomesecret():
    print('9) /usr/openv/runtime_data/callhome_secret contains:')
    if os.path.exists('/usr/openv/runtime_data/callhome_secret'):
        chsecrt = open('/usr/openv/runtime_data/callhome_secret', 'r')
        chsecrtgutz = chsecrt.read()
        log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
        log.write('10) /usr/openv/runtime_data/callhome_secret contains:')
        log.write(chsecrtgutz + '\n\n')
        print(chsecrtgutz)
        chsecrt.close()
#except IOError:
    else:
        print ("----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting" + '\n')
        log.write('----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting' + '\n\n')
    print(' ' + '\n')


# Main section
if __name__ == '__main__':
    dnsordie()
    selfname()
    printmac()
    hostschk()
    resolv_chk()
    ssl_ec2_test()
    ssl_yhoo_test()
    curltest()
    w3mit()
    get_chinfo()
    get_callhomesecret()
    trace()
    log.close()
    os.remove("/tmp/tmpfile.txt")
    os.remove("/tmp/tmpfile2.txt")
    print('Execution complete! For full output, please see the ' + log.name + ' file.')
#!/usr/bin/python
#
# Script to test access to the AutoSupport CallHome systems.
#

__author__ = 'krebel'

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

def homework():
    print("Please see the following KB articles:" + '\n')
    print("Veritas AutoSupport infrastructure update for Call Home endpoints")
    print("https://www.veritas.com/support/en_US/article.000126756" + '\n')
    print("Understanding the Call Home workflow for a NetBackup Appliance")
    print("https://www.veritas.com/support/en_US/article.000115419" + '\n')

# First check if basic DNS connectivity exists. If not, exit completely w/warning/homework.
def dnsordie():
    for word in srchstrngs:
        diginfo = commands.getoutput('dig +time=1 +tries=1 +retry=1 ' + word)
        if 'no servers could be reached' in diginfo:
            print('A DNS server is either unconfigured or unreachable on this appliance. Please configure a working DNS server.' + '\n')
            print('Note: Callhome/Autosupport servers use dynamic IP addresses that change frequently. DNS hostname resolution is required.' + '\n')
            homework()
            exit()
        else:
            continue

# Second, if we cannot connect to port 443 on receiver.appliance.veritas.com, exit completely w/warning.
def w3mit():
    blnk = ''
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    w3mout = commands.getoutput('w3m -dump https://receiver.appliance.veritas.com')
    if w3mout == blnk:
        print("1) Appliance successfully connects directly to receiver.appliance.veritas.com" + '\n\n')
        log.write("1) Appliance successfully connects directly to receiver.appliance.veritas.com" + '\n\n')
    else:
        print("Appliance unable to connect to receiver.appliance.veritas.com on TCP port 443.")
        print("This may mean that there is a routing problem, or a router, proxy server, firewall or other network device preventing connectivity.")
        homework()
        exit()

def selfname():
    self = commands.getoutput('hostname')
    print ('\n' + 'OS hostname is: ' + self + '\n\n')
    log.write('OS hostname is: ' + self  + '\n\n')

# Next two functions get the eth1 mac. TODO: make this a single smaller function.
def gethwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def printmac():
    mac = gethwaddr('eth0')
    print('2) MAC address for eth0 is: ' + mac + '\n\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('2) MAC address for eth0 is:' + mac + '\n\n')

# Check for callhome servers in hosts file which we do not want.
def hostschk():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    hstsFile = open('/etc/hosts', 'r')
    for line in hstsFile:
        for word in srchstrngs:
            if word in line:
                print('3) ' + line, end='')
                print("Please remove all references to Callhome/Autosupport servers from the /etc/hosts file." + '\n')
                homework()
                log.write('3' + line + '\n\n')
            else:
                print("3) callhome servers do not appear in /etc/hosts. (Good!)" + '\n\n')
                log.write("3) callhome servers do not appear in /etc/hosts. (Good!)" + "\n\n")
                return()
    hstsFile.close()

# A DNS server is reachable, so lets test name resolution and print out results to screen/log:
def resolv_chk():
    print('4) Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('4) Testing name resolution for all CallHome/AutoSupport servers:' + '\n')
    for word in srchstrngs:
        dignfo = commands.getoutput('dig ' + word)
        answrregex = re.compile(r'ANSWER: \d')
        hits = answrregex.search(dignfo)
        answrvalregex = re.compile(r'\d')
        answrval = answrvalregex.search(hits.group())
        if (hits.group()) == 'ANSWER: 0':
            print('DNS has no record of ' + word + '\n' + 'Please ensure the appliance can query DNS for all Callhome/Autosupport server records.' + '\n')
            homework()
        else:
            print('DNS resolved ' + word)
    print(' ' + '\n')

# Grab the SSL certificate chain.
def ssl_ec2_test():
    appmonips = commands.getoutput('dig +short ' + reg)
    tmpF = open('/tmp/tmpfile.txt', 'a')
    tmpF.write(appmonips)
    tmpF.close()
    tmpF = open('/tmp/tmpfile.txt', 'r')
    for line in tmpF:
        reverseDig = commands.getoutput('dig +short -x ' + line.strip())
    print('5) Retrieving Certificate chain:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('5) Retrieving Certificate chain:' + '\n')
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

# Can probably pull this out, but it's nice-to-have proof that we cannot make a SSL socket to anything.
def ssl_yhoo_test():
    print('6) Retrieving www.yahoo.com Certificate chain:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('6) Retrieving www.yahoo.com Certificate chain:' + '\n\n')
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

# Curl test, can we connect directly to callhome/autosupport servers:
def curltest():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("7) Curl connection attempts:" + '\n')
    log.write("Curl connection attempts:" + "\n")
    for word in curlsvrs:
        curlem = commands.getoutput('curl --connect-timeout 30 -sL -w "%{http_code} (%{url_effective})\\n" http://' + word + ' -o /dev/null')
        print(curlem)
        log.write(curlem + '\n\n')
        log.write(' ' + '\n\n')
    print('Note: HTTP codes considered as normal: 200 = OK, 401 = Authorization Required, 403 = Forbidden' + '\n\n')
    print(' ' + '\n')

# Grab traceroute results to log file.
def trace():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write("Traceroute connection attempts:" + "\n\n")
    trc = commands.getoutput('traceroute -T receiver.appliance.veritas.com')
    log.write(trc)
    # TODO: read last hostname/ip in traceroute output before triple asterisk, that could be the proxy server

# Next two functions pull the chinfo data. TODO: determine NBAPP version and pull this from proper path.
def get_chinfo():
    print('8) Gathering chinfo.txt and callhome_secret:' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('8) Gathering chinfo.txt and callhome_secret:' + '\n\n')
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
        log.write('9) /usr/openv/runtime_data/callhome_secret contains:')
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
    w3mit()
    selfname()
    printmac()
    hostschk()
    resolv_chk()
    ssl_ec2_test()
    ssl_yhoo_test()
    curltest()
    get_chinfo()
    get_callhomesecret()
    trace()
    log.close()
    os.remove("/tmp/tmpfile.txt")
    os.remove("/tmp/tmpfile2.txt")
    print('Execution complete! For full output, please see the ' + log.name + ' file.')


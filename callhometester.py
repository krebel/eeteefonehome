#!/usr/bin/python
#
# Script to test access to the AutoSupport CallHome systems
#
#

from __future__ import print_function
import os, sys, commands, re, time, socket, fcntl, struct


now = time.strftime('%Y-%m-%d_%H-%M-%S')

log = open('/tmp/chtest_' + str(now) + '.log', 'a')

# Callhome/AutoSupport servers:
reg = "api.appliance.veritas.com"
appmon = "appmon.appliance.veritas.com"
telem = "telemetry.veritas.com"
rec = "receiver.appliance.veritas.com"

srchstrngs = (reg, appmon, telem, rec)

curlsvrs = (reg, telem, rec)


def selfname():
    self = commands.getoutput('hostname')
    print ('OS hostname is: ' + self + '\n\n')
    log.write('OS hostname is: ' + self  + '\n\n')


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
#    return ':'.join(['%02x:' % ord(char) for char in info[18:24]])

def printmac():
    print('MAC address for eth0 is:')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('MAC address for eth0 is:' + '\n\n')
    mac = getHwAddr('eth0')
    print(mac)
    print(' ' + '\n')
    log.write(mac + '\n\n')

def hostschk():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    hstsFile = open('/etc/hosts', 'r')
    for line in hstsFile:
        for word in srchstrngs:
            if word in line:
                print(line, end='')
                log.write(line + '\n\n')
            else:
                print("callhome servers do not appear in /etc/hosts." + '\n\n')
                log.write("callhome servers do not appear in /etc/hosts." + "\n\n")
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
    print('dig reports for all callhome/autosupport servers:' + '\n')
    for word in srchstrngs:
        dignfo = commands.getoutput('dig ' + word)
        answrregex = re.compile(r'ANSWER: \d')
        hits = answrregex.search(dignfo)
        answrvalregex = re.compile(r'\d')
        answrval = answrvalregex.search(hits.group())
        if (hits.group()) == 'ANSWER: 0':
            print('DNS has no record of ' + word)
        else:
            print('DNS resolved ' + word)
    print(' ' + '\n\n')



def ssl_ec2_test():
    appmonips = commands.getoutput('dig +short ' + appmon)
    tmpF = open('/tmp/tmpfile.txt', 'a')
    tmpF.write(appmonips)
    tmpF.close()
    tmpF = open('/tmp/tmpfile.txt', 'r')
    for line in tmpF:
        reverseDig = commands.getoutput('dig +short -x ' + line.strip())
    print('Retrieving Certificate chain' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('Retrieving Certificate chain' + '\n')
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
    print('Retrieving www.yahoo.com Certificate chain' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('Retrieving www.yahoo.com Certificate chain' + '\n\n')
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
    print(' ' + '\n')
    tmpF2.close()





def curltest():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("Curl connection attempts:" + '\n')
    log.write("Curl connection attempts:" + "\n")
    for word in curlsvrs:
        curlem = commands.getoutput('curl --connect-timeout 30 -sL -w "%{http_code} (%{url_effective})\\n" http://' + word + ' -o /dev/null')
        print(curlem)
        log.write(curlem + '\n\n')
        log.write(' ' + '\n\n')
    print('Note: HTTP codes considered as normal: 200 = OK, 401 = Authorization Required, 403 = Forbidden' + '\n\n')
    print(' ' + '\n')

def trace():
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("Traceroute connection attempts:" + '\n\n')
    log.write("Traceroute connection attempts:" + "\n\n")
    trc = commands.getoutput('traceroute receiver.appliance.veritas.com')
    print(trc)
    print(' ' + '\n')
    # TODO: read last hostname/ip in traceroute output before triple asterisk, that could be the proxy server


def get_chinfo():
    print('Gathering chinfo.txt and callhome_secret' + '\n')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('Gathering chinfo.txt and callhome_secret' + '\n\n')
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
    print('/usr/openv/runtime_data/callhome_secret contains:')
    if os.path.exists('/usr/openv/runtime_data/callhome_secret'):
        chsecrt = open('/usr/openv/runtime_data/callhome_secret', 'r')
        chsecrtgutz = chsecrt.read()
        log.write('/usr/openv/runtime_data/callhome_secret contains:')
        log.write(chsecrtgutz + '\n\n')
        print(chsecrtgutz)
        chsecrt.close()
#except IOError:
    else:
        print ("----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting" + '\n')
        log.write('----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting' + '\n\n')
    print(' ' + '\n')



#### Main section
if __name__ == '__main__':
    selfname()
    printmac()
    hostschk()
    ssl_ec2_test()
    ssl_yhoo_test()
    curltest()
    trace()
    get_chinfo()
    get_callhomesecret()
    log.close()
    os.remove("/tmp/tmpfile.txt")
    os.remove("/tmp/tmpfile2.txt")
    print('Execution complete! For full output, please see the ' + log.name + ' file.')
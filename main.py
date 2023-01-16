from scapy.all import *

interface = sys.argv[1]
filename = sys.argv[2]
ssid_list = []
mac = "11:22:33:55:77:"
addr = 16

with open(filename) as f:
    for line in f:
        ssid_list.append(line)

while True:
    for i in range(len(ssid_list)):
        #ssid = i.encode('UTF-8')
        ssid = ssid_list[i]
        haddr = hex(addr).lstrip("0x")
        
        dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = mac+haddr, addr3 = mac+haddr)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        rsn = Dot11EltRSN()
        if addr >= 255:
            addr = 16
        addr = addr + 1
        
        frame = RadioTap(Rate=2)/dot11/beacon/essid/rsn
        
        sendp(frame, iface=interface, inter=0.100, loop=0)

        if i == len(ssid_list)-1:
            i = 0

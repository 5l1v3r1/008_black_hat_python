# /usr/bin/python python3
# -*- coding:utf-8 -*-
#################################################
# Filename: scratch_taiyuan_house_info.py
# Author:   jerry_0824
# Email:    63935127##qq.com
# Phone:    +86-155-8287-7999
# Date:     2016-03-01
# Version:  v1.0.0
#################################################

__author__ = 'jerry_0824'

# pip3 install scapy-python3
from scapy.all import *

# our packet callback
def packet_callback(packet):
    print(packet.show())

# main
def main():
    # started time
    time_started = time.time()
    print("\nstarted time: %s" % time.ctime(time_started))

    # fire up our sniffer
    sniff(prn=packet_callback,count=1)

    # finished time
    _time_finished = time.time() - time_started
    print("\nsince initial elapsed %.2f s" % (_time_finished))

if __name__ == "__main__":
    sys.exit(main())
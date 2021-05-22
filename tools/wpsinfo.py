#!/usr/bin/env python3

"""
wpsinfo: Get detailed access point information from WPS frames.

Copyright (c) 2021, soxrok2212 <soxrok2212@gmail.com>
SPDX-License-Identifier: GPL-3.0+

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

from scapy.all import *
import netifaces
import time
import sys
import getopt
import logger
import interruptingcow

networks = {}

def show_version(version):
    print('wpsinfo ' + version)

def show_help(version):
    help = '''wpsinfo {}: Get detailed access point information form WPS frames.
Copyright (c) 2021, soxrok2212 <soxrok2212@gmail.com>

Usage: python3 wpsinfo.py <arguments>

Required Arguments:

        -i, --interface\t: Interface

Options Arguments:

        -c, --channel\t: Channel of target
        -b, --bssid\t: BSSID of target

    '''.format(version)
    print(help)

def get_interface(interface):
    addrs = netifaces.ifaddresses(interface)	
    iface = addrs[netifaces.AF_LINK][0]['addr']
    return iface

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode()
        try:
            signal = pkt.dBm_AntSignal
        except:
            signal = 'n/a'
        channel = pkt[Dot11Beacon].network_stats().get('channel')
        net = []
        net.append(ssid)
        net.append(signal)
        net.append(channel)
        networks[bssid] = net

def change_channel(interface, channel):
    cmd = 'iw dev %s set channel %d' % (interface, channel)
    os.system(cmd)
    time.sleep(0.5)
    return 0

def populate_networks(interface, channel):
    if not channel:
        for i in range(1,12):
            change_channel(interface, i)
            print('Scanning channel ' + str(i), end='\r')
            sniff(iface=interface, prn=packet_handler, timeout=1)
    else:
        change_channel(interface, channel)
        print('Scanning channel ' + str(channel), end='\r')
        sniff(iface=interface, prn=packet_handler, timeout=1)

def get_essid(interface, bssid):
    if bssid in networks:
        essid = networks[bssid][0]
    else:
        print('Couldn\'t find network with bssid %s' % (bssid))
        exit(1)
    return essid

def probe_network(interface, channel, bssid, essid):
    src = mac2str(get_interface(interface))
    dst = mac2str(bssid)
    change_channel(interface, channel)

    pkt = RadioTap()/Dot11(addr1=dst, addr2=src, addr3=src)\
        /Dot11ProbeReq()\
        /Dot11Elt(ID=0, info=essid)\
        /Dot11Elt(ID=1, info='\x82\x84\x8b\x96\x0c\x12\x18')\
        /Dot11Elt(ID=50, info='\x30\x48\x60\x6c')\
        /Dot11Elt(ID=3, info=chr(channel))
    answer = srp1(pkt, iface = interface, verbose=0)
    answer.show()

def sniff_network(interface, channel, bssid, essid):
    if not essid:
        populate_networks(interface, channel)
        essid = get_essid(interface, bssid)
    probe_network(interface, channel, bssid, essid)

def main():
    version = '1.0'

    # cli options
    interface = None
    channel = None
    bssid = None
    essid = None
    probe_all = None

    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'i:c:b:e:pVh', ['interface=',
                                                                        'channel=',
                                                                        'bssid=',
                                                                        'essid=',
                                                                        'probe-all',
                                                                        'version',
                                                                        'help'])
    except getopt.GetoptError as err:
        print(err)
        show_help(version)
        sys.exit(2)

    for opt, arg in options:
        if opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-c', '--channel'):
            channel = int(arg)
        elif opt in ('-b', '--bssid'):
            bssid = arg.lower()
        elif opt in ('-e', '--essid'):
            essid = arg
        elif opt in ('-p', '--probe_all'):
            probe_all = True
        elif opt in ('-V', '--version'):
            show_version(version)
        elif opt in ('-h', '--help'):
            show_help(version)
        else:
            opt_err(opt, version)

    if len(sys.argv) <= 1:
        show_help(version)
    if not channel and not bssid: # probe all
        print('Probing all networks')
    elif channel and bssid and not essid: # get ssid
        print('Probing %s' % (bssid))
        sniff_network(interface, channel, bssid, None)
    elif channel and bssid and essid: # have everything, probe it!
        print('Probing %s' %(essid))
        sniff_network(interface, channel, bssid, essid)


if __name__ == "__main__":
    main()

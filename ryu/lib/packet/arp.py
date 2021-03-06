# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from ryu.ofproto import ether
from ryu.lib import ip
from ryu.lib import mac
from . import packet_base

ARP_HW_TYPE_ETHERNET = 1  # ethernet hardware type

# arp operation codes
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REV_REQUEST = 3
ARP_REV_REPLY = 4


class arp(packet_base.PacketBase):
    """ARP (RFC 826) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    hwtype         ar$hrd
    proto          ar$pro
    hlen           ar$hln
    plen           ar$pln
    opcode         ar$op
    src_mac        ar$sha
    src_ip         ar$spa
    dst_mac        ar$tha
    dst_ip         ar$tpa
    ============== ====================
    """

    _PACK_STR = '!HHBBH6sI6sI'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, hwtype=ARP_HW_TYPE_ETHERNET, proto=ether.ETH_TYPE_IP,
                 hlen=6, plen=4, opcode=ARP_REQUEST,
                 src_mac=mac.haddr_to_bin('ff:ff:ff:ff:ff:ff'),
                 src_ip=ip.ipv4_to_bin('0.0.0.0'),
                 dst_mac=mac.haddr_to_bin('ff:ff:ff:ff:ff:ff'),
                 dst_ip=ip.ipv4_to_bin('0.0.0.0')):
        super(arp, self).__init__()
        self.hwtype = hwtype
        self.proto = proto
        self.hlen = hlen
        self.plen = plen
        self.opcode = opcode
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dst_mac = dst_mac
        self.dst_ip = dst_ip
        self.length = arp._MIN_LEN

    @classmethod
    def parser(cls, buf):
        (hwtype, proto, hlen, plen, opcode, src_mac, src_ip,
         dst_mac, dst_ip) = struct.unpack_from(cls._PACK_STR, buf)
        return cls(hwtype, proto, hlen, plen, opcode, src_mac, src_ip,
                   dst_mac, dst_ip), None

    def serialize(self, payload, prev):
        return struct.pack(arp._PACK_STR, self.hwtype, self.proto,
                           self.hlen, self.plen, self.opcode,
                           self.src_mac, self.src_ip, self.dst_mac,
                           self.dst_ip)


def arp_ip(opcode, src_mac, src_ip, dst_mac, dst_ip):
    """A convenient wrapper for IPv4 ARP for Ethernet.

    This is an equivalent of the following code.

        arp(ARP_HW_TYPE_ETHERNET, ether.ETH_TYPE_IP, \
               6, 4, opcode, src_mac, src_ip, dst_mac, dst_ip)
    """
    return arp(ARP_HW_TYPE_ETHERNET, ether.ETH_TYPE_IP,
               6,  # ether mac address length
               4,  # ipv4 address length,
               opcode, src_mac, src_ip, dst_mac, dst_ip)

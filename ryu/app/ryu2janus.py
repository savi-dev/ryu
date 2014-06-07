# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2013, The SAVI Project.
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

import logging
import struct
import httplib
import json
import gflags
import ctypes

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller import api_db
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import BROADCAST, haddr_to_str, ipaddr_to_str, is_multicast, haddr_to_bin
from ryu.lib.lldp import ETH_TYPE_LLDP
from janus.network.of_controller.janus_of_consts import JANEVENTS, JANPORTREASONS
from janus.network.of_controller.event_contents import EventContents
from ryu.ofproto import nx_match

FLAGS = gflags.FLAGS
gflags.DEFINE_string('janus_host', '127.0.0.1', 'Janus host IP address')
gflags.DEFINE_integer('janus_port', '8091', 'Janus admin API port')

OFP_DEFAULT_PRIORITY=32565

LOG = logging.getLogger('ryu.app.ryu2janus')

class Ryu2JanusForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {
        'api_db': api_db.API_DB,
    }

    def __init__(self, *args, **kwargs):
        super(Ryu2JanusForwarding, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.api_db = kwargs.get('api_db', None)

        # Janus address
        self.host = FLAGS.janus_host
        self.port = FLAGS.janus_port
        self.url_prefix = '/v1.0/events/0'

    def _forward2Controller(self, method, url, body=None, headers=None):
        conn = httplib.HTTPConnection(self.host, self.port)
        conn.request(method, url, body, headers)
        res = conn.getresponse()
        print "\n"
        if res.status in (httplib.OK,
                          httplib.CREATED,
                          httplib.ACCEPTED,
                          httplib.NO_CONTENT):
            return res

        raise httplib.HTTPException(
            res, 'code %d reason %s' % (res.status, res.reason),
            res.getheaders(), res.read())

    def _install_modflow(self, msg, in_port, src, dst = None, eth_type = None, actions = None,
                         priority = OFP_DEFAULT_PRIORITY,
                         idle_timeout = 0, hard_timeout = 0, cookie = 0):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        if LOG.getEffectiveLevel() == logging.DEBUG:
            if len(actions) > 0:
                act = "out to "
                for action in actions:
                    act += str(action.port) + ","
            else:
                act = "drop"
            LOG.debug("installing flow from port %s, src %s to dst %s, action %s", in_port, haddr_to_str(src), haddr_to_str(dst), act)
        if actions is None:
            actions = []

        # install flow
        rule = nx_match.ClsRule()
        if in_port is not None:
            rule.set_in_port(in_port)
        if dst is not None:
            rule.set_dl_dst(dst)
        if src is not None:
            rule.set_dl_src(src)
        if eth_type is not None:
            rule.set_dl_type(eth_type)

        datapath.send_flow_mod(
            rule = rule, cookie = cookie, command = datapath.ofproto.OFPFC_ADD,
            idle_timeout = idle_timeout, hard_timeout = hard_timeout,
            priority = priority,
            buffer_id = 0xffffffff, out_port = ofproto.OFPP_NONE,
            flags = ofproto.OFPFF_SEND_FLOW_REM, actions = actions)

    def _modflow_and_drop_packet(self, msg, src, dst, priority = OFP_DEFAULT_PRIORITY, idle_timeout = 0):
        LOG.info("installing flow for dropping packet %s, %s" %(msg.in_port, haddr_to_str(dst)))
        datapath = msg.datapath
        in_port = msg.in_port

        self._install_modflow(msg, in_port, src, dst, actions = [], priority = priority, idle_timeout = idle_timeout)
        datapath.send_packet_out(msg.buffer_id, in_port, [])

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            LOG.info("port added %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_ADD
            method = 'POST'
        elif reason == ofproto.OFPPR_DELETE:
            LOG.info("port deleted %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_DELETE
            method = 'PUT' # 'DELETE' doesn't support a body in the request
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
            reason_id = JANPORTREASONS.JAN_PORT_MODIFY
            method = 'PUT'
        else:
            LOG.info("Illegal port state %s %s", port_no, reason)
            LOG.info("UNKNOWN PORT STATUS REASON")
            raise

        # TO DO: Switch to using EventContents class
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_PORTSTATUS,
                                        'datapath_id': msg.datapath.id,
                                        'reason': reason_id, 'port': port_no}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING PORT STATUS TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #print "My packet in handler"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        contents = EventContents()
        contents.set_dpid(datapath.id)
        contents.set_buff_id(msg.buffer_id)

        dl_dst, dl_src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        if _eth_type == ETH_TYPE_LLDP:
            # Don't forward LLDP packets to Janus
            return

        if dl_dst != BROADCAST and is_multicast(dl_dst):
            # drop and install rule to drop
            self._modflow_and_drop_packet(msg, None, dl_dst, 100, idle_timeout = 360)
            return

        contents.set_in_port(msg.in_port)
        contents.set_dl_dst(haddr_to_str(dl_dst))
        contents.set_dl_src(haddr_to_str(dl_src))
        contents.set_eth_type(_eth_type)

        if _eth_type == 0x806: # ARP
            HTYPE, PTYPE, HLEN, PLEN, OPER, SHA, SPA, THA, TPA = struct.unpack_from('!HHbbH6s4s6s4s', buffer(msg.data), 14)
            contents.set_arp_htype(HTYPE)
            contents.set_arp_ptype(PTYPE)
            contents.set_arp_hlen(HLEN)
            contents.set_arp_plen(PLEN)
            contents.set_arp_oper(OPER)

            contents.set_arp_sha(haddr_to_str(SHA))
            contents.set_arp_spa(ipaddr_to_str(SPA))
            contents.set_arp_tha(haddr_to_str(THA))
            contents.set_arp_tpa(ipaddr_to_str(TPA))
            if False: #self.api_db:
                mac_address = self.api_db.get_mac_address(ipaddr_to_str(TPA))
                LOG.info("retrived mac address for %s is %s, requested by %s" %(ipaddr_to_str(TPA), mac_address, ipaddr_to_str(SPA))) 
                if mac_address:
                    mydata = ctypes.create_string_buffer(42)
                    struct.pack_into('!6s6sHHHbbH6s4s6s4s', mydata, 0, SHA, haddr_to_bin(mac_address), _eth_type, HTYPE,
                                 PTYPE, HLEN, PLEN, 2, haddr_to_bin(mac_address), TPA, SHA, SPA)

                    #LOG.info("handled arp packet: %s, %s, %s, %s requested by %s, %s", dpid, out_port,
                    #     mac.haddr_to_str(src_mac), mac.ipaddr_to_str(src_ip),
                    #     mac.haddr_to_str(src), mac.ipaddr_to_str(dst_ip))
                    actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
                    self._drop_packet(msg)
                    datapath.send_packet_out(actions = actions, data = mydata)
                    return
                #else:
                #    self._drop_packet(msg)
                #    return
       
        method = 'POST'
        body = {'of_event_id': JANEVENTS.JAN_EV_PACKETIN}
        body.update(contents.getContents())
        body = json.dumps({'event': body})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING PACKET TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath_id
        ports = msg.ports

        method = 'PUT'
        body = json.dumps({'event': {'of_event_id': JANEVENTS.JAN_EV_FEATURESREPLY,
                                        'datapath_id': dpid, 'ports': ports.keys()}})
        header = {"Content-Type": "application/json"}

        url = self.url_prefix
        LOG.info("FORWARDING FEATURES REPLY TO JANUS: body = %s", body)
        self._forward2Controller(method, url, body, header)

    def _drop_packet(self, msg):
        datapath = msg.datapath
        datapath.send_packet_out(msg.buffer_id, msg.in_port, [])



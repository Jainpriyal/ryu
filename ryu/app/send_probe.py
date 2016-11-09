# SEnding probe packet to calculate latency 

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.controller.controller import Datapath
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
	self.topology_api_app = self
        #self.db = Datapath()
        #print "llllll", self.db
        #self.send_packet_out(self.db)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def send_packet_out(self, db):
        print "inside send_packet_out"
        db.id = "0000fef7b1fb3548"
    	ofp = db.ofproto
    	ofp_parser = db.ofproto_parser
        #buffer_id = OFP_NO_BUFFER
        buffer_id = 0xffffffff
    	actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
    	req = ofp_parser.OFPPacketOut(db, buffer_id,
                                  ofp.OFPP_NONE, actions)
	print "req:", req
    	datapath.send_msg(req)

#     https://github.com/osrg/ryu/blob/master/ryu/controller/controller.py#L385
#    def send_packet_out(self, buffer_id=0xffffffff, in_port=None,
#                       actions=None, data=None):
#        if in_port is None:
#            in_port = self.ofproto.OFPP_NONE
#        packet_out = self.ofproto_parser.OFPPacketOut(
#            self, buffer_id, in_port, actions, data)
#    self.send_msg(packet_out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
	print "datapath id:", datapath, type(datapath)
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        self.send_packet_out(datapath, buffer_id=msg.buffer_id, in_port=msg.in_port)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
    	switch_list = get_switch(self.topology_api_app, None)
	print "switch:",switch_list[0], type(switch_list[0])
    	switches=[switch.dp.id for switch in switch_list]
        print "\nswitches", switches
    	links_list = get_link(self.topology_api_app, None)
    	links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        print "\nlinks:", links

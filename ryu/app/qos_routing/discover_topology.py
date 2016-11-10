### Code to discover Network topology

import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import constants 


CONF = cfg.CONF


class TopologyDiscovery(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TopologyDiscovery, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.name = "awareness"
        self.link_table = {}    #linktoport table       # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.sw_host_table = {}       # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # dpip->port_num
        self.access_ports = {}       # dpid->port_num
        self.interior_ports = {}     # dpid->port_num
	self.switches = []
        self.graph = nx.DiGraph()
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}
        self.shortest_paths = None
        self.topo_discover_thread = hub.spawn(self._topo_discovery)

    def _topo_discovery(self):
	"""
        Function is called by spawning HUB function
	It is called in every 5sec
	"""
        count = 0
	while True:
              self.get_topology(None)
	      self.show_topology()
	      hub.sleep(constants.TOPOLOGY_DISCOVERY_TIME)
    # Get list of switches
    def get_switches(self):
	return self.switches

    # Get list of links
    def get_links(self):
	return self.link_table
   


    # Capture all the events: Switch Enter,Leave, Port Add, delete, modify, Link Add, delete
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    @set_ev_cls(events)
    def get_topology(self, ev):
	"""
	   Get the details of switches and links
	"""
        print "\n Discovering topology............ "
	switch_list = get_switch(self.topology_api_app, None)
	self.switches = [switch.dp.id for switch in switch_list]
        links = get_link(self.topology_api_app, None)
	### Need to make link table afer getting link details link_table 
        self.link_table = links

    def show_topology(self):
	"""
	   Show Final topology
        """
        print "\n ******* Topology Details *********"
	print "Switches:", self.switches 
	print "links:", self.link_table


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
            Hanle the packet in packet, and register the access info.
        """
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac

            # Record the access info
#            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
	 

import logging
import struct
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
import discover_topology
import latency_detector

CONF = cfg.CONF


class QosForwarding(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "topology_discovery": discover_topology.DiscoverTopology,
        "latency_calculator": latency_detector.LatencyCalculator}


    def __init__(self, *args, **kwargs):
        super(QosForwarding, self).__init__(*args, **kwargs)
        self.name = 'qos_forwarding'
        self.topology = kwargs["topology_discovery"]
        self.latency_calculator = kwargs["latency_calculator"]
        self.datapaths = {}
        self.latency_weight = 10 #weight assigned to latency
        self.measure_thread = hub.spawn(self._metric_calculator)        
         
    def _metric_calculator(self):
	i=0
	while True:
	     self._calculate_link_cost()
	     if i ==5:
	        self.show_link_cost()
		self.trigger()
		i=0
             else:
		i=i+1
             hub.sleep(1)
	
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _calculate_link_cost(self):
	"""
	    Function to calculate cost of links
	"""
        try:
            for src in self.topology.database:
                for dst in self.topology.database[src]:
		    if src == dst:
                        self.topology.database[src][dst]['cost'] = 0
                        continue
                    latency = self.topology.database[src][dst]['latency']
		    cost = self.latency_weight*latency
                    self.topology.database[src][dst]['cost'] = cost
        except Exception as ex:
            if self.topology is None:
                self.topology = lookup_service_brick('topologydiscovery')
            return

    def show_link_cost(self):
	"""
	    Show link cost
        """
        if constants.SHOWCOST and self.topology is not None and self.topology.database.number_of_nodes()>0:
            self.logger.info("\nsrc-dpid    dst-dpid               Cost")
            self.logger.info("-----------------------------------------------")
            for src in self.topology.database:
                for dst in self.topology.database[src]:
                    cost = self.topology.database[src][dst]['cost']
                    self.logger.info("%s<-->%s : %s" % (src, dst, cost))

    def trigger(self):
	for src in self.topology.database:
                for dst in self.topology.database[src]:
			self.calculate_shortest_cost_path(self.topology.database, src, dst)

    def calculate_shortest_cost_path(self, topology, src, dst):
	"""
	   This function takes the cost of every link and calculates the shortest path between source and destination
	   whenever a packet comes in, first it will check the ip and the source and destination, it will also check dscp field
	   then it will call dijkstra algo to find shortest cost path 
	"""
        if topology is not None:
	     path = nx.dijkstra_path(topology, source= src, target=dst, weight='cost')
	     return path
	else:
	     return None

    def get_host_location(self, datapath_id, in_port, src_ip, dst_ip):
        """
	  this function will return dpid of switches connected with source and destination host
	  after getting dpid of source and destination switch try calculating shortest path between destination and switch
        """
	src_dpid = datapath_id
	dst_dpid = None
        source_location = self.topology.retrieve_dpid_connected_host(src_ip)
	# check if inport of switch is the port that is connected with host        
	if in_port in self.topology.switch_host_ports[datapath_id]:
		if(datapath_id, in_port)== source_location:
			src_dpid = source_location[0]
		else:
		        return None
        destination_location = self.topology.retrieve_dpid_connected_host(dst_ip)
	if destination_location:
		dst_dpid = destination_location[0]
        	print "\n retrieve_dpid_connected_host:", src_dpid, dst_dpid
	return src_dpid, dst_dpid

    def get_switch_port_pair(self, src_dpid, dst_dpid):
	"""
	get port number of src_dpid and dst_pid from switch adjacency matrix
	"""
	print "\n inside get_switch_port_par"
        if (src_dpid, dst_dpid) in self.topology.switch_link_table:
	    return switch_link_table[(src_dpid, dst_dpid)]
	else:
	    self.logger.info("No link between {}, {}".format(src_dpid, dst_dpid))
	    return None

    def install_flows(self, path, flow_info):
	"""
	install flows in all switches
	get the port number and links for all switches 
	"""
	print "adding flow"
        if len(path)>1:
	    for i in range(0, len(path)):
		ports = self.get_switch_port_pair(path[i], path[i+1])
		src_port = port[0]
		dst_port = port[1]
                self.build_flow_mod(path[i],src_port, dst_port, flow_info)
                
				
    def build_flow_mod(self, datapath, src_port, dst_port, flow_info):
	"""
	Build flow mod packets to be installed in switch
	"""
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port)) ## add action to send to destination port

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.send_flow_mod(datapath, 1, match, actions,
                      idle_timeout=15, hard_timeout=60)

    def send_flow_mod(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    def send_packet_out(self):
	"""
	send packet out message
	"""
	print "send packet out"

    def handle_arp_request(self):
	"""
	handle arp request coming to controller
	"""
	print "handle arp request"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
	Handle packet in-packet
        '''
        print "handle packet in handler"
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
	arp_packet = pkt.get_protocol(arp.arp)
	if arp_packet:
	    # if arp request, then flood the packet for now
            print "flooding arp request"
            in_port = msg.match['in_port']
            out_port = ofproto.OFPP_FLOOD
	    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port,actions=actions)
	    datapath.send_msg(out)
        ip_packet = pkt.get_protocol(ipv4.ipv4)
	if ip_packet:
	    print "\n if ping packet"
	    src_ip = ip_packet.src  # source ip of packet
	    dst_ip = ip_packet.dst  # destination ip of packet
	    eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
            print "src_ip, dst_ip", src_ip, dst_ip 
            location = self.get_host_location(datapath.id, in_port, src_ip, dst_ip)
	    # perform other operations if source switch and destination switch location is found 
	    if location and location[1]:
		src_dpid = location[0]
		dst_dpid = location[1]
	    	print "\n ****** print src_dpid {} dst_dpid {}".format(src_dpid, dst_dpid)
            	path = self.calculate_shortest_cost_path(self.topology.database, src_dpid, dst_dpid)
            	self.logger.info("shortest path: {} <----->{}: {}".format(src_ip, dst_ip, path))
            	flow_info = [eth_type, src_ip, dst_ip, in_port]
            	self.install_flows(path, flow_info ) # install_flows will install flows in corresponding OVS



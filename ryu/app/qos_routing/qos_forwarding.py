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
	self.weighted_cost = 100
        self.measure_thread = hub.spawn(self._metric_calculator)        
         
    def _metric_calculator(self):
	i=0
	print "inside metric calculator"
	while True:
	     self._calculate_link_cost()
	     if i ==5:
	        self.show_link_cost()
		i=0
             else:
		i=i+1
             hub.sleep(constants.COST_CALCULATION_PERIOD)
	
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
                    cost = self.topology.database[src][dst].get('cost')
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
	     self.topology.database[dst][src]['cost']=self.weighted_cost*self.topology.database[dst][src]['cost']
	     self.topology.database[src][dst]['cost']=self.weighted_cost*self.topology.database[src][dst]['cost']
	     self.show_link_cost()
	     path = nx.dijkstra_path(topology, source= src, target=dst, weight='cost')
	     total_cost = nx.dijkstra_path_length(topology, source= src, target=dst, weight='cost')
	     return path, total_cost
	else:
	     return None

    def calculate_shortest_hop_path(self, topology, src, dst):
        """
           This function takes the cost of every link and calculates the shortest path between source and destination
           whenever a packet comes in, first it will check the ip and the source and destination, it will also check dscp field
           then it will call dijkstra algo to find shortest cost path 
        """
        if topology is not None:
	     total_cost = 0
	     self.topology.database[dst][src]['cost']=self.weighted_cost*self.topology.database[dst][src]['cost']
             self.topology.database[src][dst]['cost']=self.weighted_cost*self.topology.database[src][dst]['cost']
             self.show_link_cost() 
	     path = nx.shortest_path(topology, source= src, target=dst)
	     if len(path)>1:
	     	for i in range(len(path)-1):
			total_cost = total_cost + self.topology.database[path[i]][path[i+1]]['cost']
	     return path, total_cost
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
        	self.logger.info("\nSource dpid: {} Destination dpid: {}:".format(src_dpid, dst_dpid))
	return src_dpid, dst_dpid

    def get_switch_port_pair(self, src_dpid, dst_dpid):
	"""
	get port number of dpids from switch adjacency matrix
	"""
        if (src_dpid, dst_dpid) in self.topology.switch_link_table:
	    return self.topology.switch_link_table[(src_dpid, dst_dpid)]
	else:
	    self.logger.info("No link between {}, {}".format(src_dpid, dst_dpid))
	    return None

    def get_destination_port(self, destination_ip):
        """
	    get port of the switch from which destination host is attached
        """
        if self.topology.switch_host_access_table:
            if isinstance(self.topology.switch_host_access_table.values()[0], tuple):
                for values in self.topology.switch_host_access_table.keys():
                    if destination_ip == self.topology.switch_host_access_table[values][0]:
                        destination_port = values[1]
                        return destination_port
        return None


    def install_flows(self, path, flow_info, msg, queue_set):
	"""
	install flows in all switches
	get the port number and links for all switches 
	"""
	self.logger.info("\n Installing flows in datapaths......")
	in_port = flow_info[3]
	###### Here installing flows for internal switches 
        ## in_port is the port of switch from which data is coming
	## out_port is the port of switch from which data will go 
        if len(path) > 2:
            for i in range(1, len(path)-1):
                ports_in = self.get_switch_port_pair(path[i-1], path[i]) # port from which data is coming
                ports_out = self.get_switch_port_pair(path[i], path[i+1])
                if ports_in and ports_out:
                    src_port, dst_port = ports_in[1], ports_out[0] ## get in_port and out_port
                    src_dpid = self.datapaths[path[i]]
		    rev_info= (flow_info[0], flow_info[2], flow_info[1])
                    self.build_flow_mod(src_dpid, src_port, dst_port, flow_info, queue_set)
                    self.build_flow_mod(src_dpid, dst_port, src_port, rev_info, queue_set)
                    self.logger.info("Installing flows in internal switches ")

	if len(path)>1:
	    # flow entry for source host to first switch in path
	    ports = self.get_switch_port_pair(path[0], path[1])
            if ports is None:
                self.logger.info("Port for first hop is not found")
                return
            dst_port = ports[0]
	    src_dpid = self.datapaths[path[0]]
            self.build_flow_mod(src_dpid, in_port, dst_port, flow_info, queue_set) # install flow
	    rev_info = (flow_info[0], flow_info[2], flow_info[1])
            self.build_flow_mod(src_dpid, dst_port, in_port, rev_info, queue_set) # install flow for back trip
            self.send_packet_out(src_dpid, msg.buffer_id, in_port, dst_port, msg.data, queue_set) # send packet out message

	    # flow entry from last switch to destination host
	    ports = self.get_switch_port_pair(path[-2], path[-1])
            if ports is None:
                self.logger.info("Port is not found")
                return
            src_port = ports[1]
	    dst_port = self.get_destination_port(flow_info[2]) # get port from which host is connected with switch
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            dst_dpid = self.datapaths[path[-1]]
	    back_info = (flow_info[0], flow_info[2], flow_info[1])
            self.build_flow_mod(dst_dpid, src_port, dst_port, flow_info, queue_set)
            self.build_flow_mod(dst_dpid, dst_port, src_port, back_info, queue_set)
	else:
	    dst_dpid = self.datapaths[path[0]]
            dst_port = self.get_destination_port(flow_info[2]) # flow_info[2] is destination ip
            if dst_port is None:
                self.logger.info("Destination port is not present")
                return
            self.build_flow_mod(dst_dpid, in_port, dst_port, flow_info, queue_set) 
	    # install flow for reverse path
	    back_info = (flow_info[0], flow_info[2], flow_info[1])
            self.build_flow_mod(dst_dpid, dst_port, in_port, back_info, queue_set)
            self.send_packet_out(dst_dpid, msg.buffer_id, in_port, dst_port, msg.data, queue_set)

	    """
	    for i in range(0, len(path)-1):
		ports = self.get_switch_port_pair(path[i], path[i+1])
		print "\n path[i], path[i+1]:",path[i],path[i+1]
		print "\n ports:",ports
		src_port = ports[0]
		dst_port = ports[1]
		datapath = self.datapaths[path[i]]
                self.build_flow_mod(datapath,src_port, dst_port, flow_info)
		self.build_flow_mod(datapath, dst_port, src_port, flow_info)                
		src_port = self.get_destination_port(flow_info[1])		
                self.build_flow_mod(datapath, dst_port, src_port, flow_info)

		src_port = ports[1]
                dst_port = ports[0]
                datapath = self.datapaths[path[i+1]]
                self.build_flow_mod(datapath,src_port, dst_port, flow_info)
                self.build_flow_mod(datapath, dst_port, src_port, flow_info)
                dst_port = self.get_destination_port(flow_info[2])
		src_port = ports[0]
		if dst_port:
		        print "\n installing datapath for:",path[-1]
			print "\n\n0000000source port:", src_port, dst_port
			# installing flow for final datapath
			final_dp = self.datapaths[path[-1]]
	        	self.build_flow_mod(final_dp,src_port, dst_port, flow_info)
	      """
    def build_flow_mod(self, datapath, src_port, dst_port, flow_info, queue_set):
	"""
	Build flow mod packets to be installed in switch
	"""
        parser = datapath.ofproto_parser
        actions = []
	if queue_set:
            actions.append(parser.OFPActionSetQueue(1))
	actions.append(parser.OFPActionOutput(dst_port)) ## add action to send to destination port
        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.send_flow_mod(datapath, 1, match, actions,
                      idle_timeout=40, hard_timeout=100)

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


    def build_packet_out(self, datapath, buffer_id, src_port, dst_port, data, queue_set= False):
        """
            Build packet out object.
        """
        actions = []
        if queue_set:
	    actions.append(datapath.ofproto_parser.OFPActionSetQueue(1))
	if dst_port:
	    actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port)) ## add action to send to destination port	
        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data, queue_set= False):
        """
            Send packet out packet to assigned datapath.
        """
        out = self.build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data, queue_set) 
        if out:
            datapath.send_msg(out)

    ####### Need to modify this function
    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.topology.switch_host_ports:
            for port in self.topology.switch_host_ports[dpid]:
                if (dpid, port) not in self.topology.switch_host_access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self.build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def handle_arp_request(self, msg, srcip, dstip):
	"""
	handle arp request coming to controller
	"""
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        result = self.topology.retrieve_dpid_connected_host(dstip)
        if result:  
            dst_datapath, out_port = result[0], result[1]
            datapath = self.datapaths[dst_datapath]
            out = self.build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.flood(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
	Handle packet in-packet
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
	arp_packet = pkt.get_protocol(arp.arp)
	if arp_packet:
	    # if arp request, then flood the packet for now
            self.logger.info("\nHandling arp request...")
            in_port = msg.match['in_port']
	    self.handle_arp_request(msg, arp_packet.src_ip, arp_packet.dst_ip)
         #    out_port = ofproto.OFPP_FLOOD
	 #   actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
         #   out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port,actions=actions)
	 #   datapath.send_msg(out)
        ip_packet = pkt.get_protocol(ipv4.ipv4)
	if ip_packet:
	    self.logger.info("\nHandling ip packets...")
	    dscp_val = ip_packet.tos
	    src_ip = ip_packet.src  # source ip of packet
	    dst_ip = ip_packet.dst  # destination ip of packet
	    eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
	    self.logger.info("Source ip address: {}, Destination ip address {}".format(src_ip, dst_ip))
            location = self.get_host_location(datapath.id, in_port, src_ip, dst_ip)
	    # perform other operations if source switch and destination switch location is found 
	    if location and location[1]:
		dscp_val = ip_packet.tos
		src_dpid = location[0]
		dst_dpid = location[1]
		if dscp_val:
			queue_set = True
			self.logger.info("\nPackets are marked with DSCP, tos val is {}".format(dscp_val))
            		path, final_cost = self.calculate_shortest_cost_path(self.topology.database, src_dpid, dst_dpid)
            		self.logger.info("\n\nShortest Cost Path: Cost: {} <----->{}: {} {}".format(src_ip, dst_ip, path, final_cost))
		else:
			queue_set = False
			self.logger.info("\nPackets are not marked with DSCP")
			path, final_cost = self.calculate_shortest_hop_path(self.topology.database, src_dpid, dst_dpid)
			self.logger.info("\n\nShortest Hop  Path: Cost {} <----->{}: {} {}".format(src_ip, dst_ip, path, final_cost))
            	flow_info = [eth_type, src_ip, dst_ip, in_port]
            	self.install_flows(path, flow_info, msg, queue_set) # install_flows will install flows in corresponding OVS



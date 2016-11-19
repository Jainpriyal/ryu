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


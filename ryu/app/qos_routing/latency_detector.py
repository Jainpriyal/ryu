#################### Latency Calculator #######################
# sends echo request within every 0.05sec


###############################################################
from __future__ import division
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology.switches import Switches
from ryu.topology.switches import LLDPPacket
import networkx as nx
import time
import constants


CONF = cfg.CONF


class LatencyCalculator(app_manager.RyuApp):
    """
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LatencyCalculator, self).__init__(*args, **kwargs)
        self.name = 'latencycalculator'
        self.sending_echo_request_interval = 0.05
        # Get the active object of swicthes and nwtopology module.
        # So that this module can use their data.
        self.sw_module = lookup_service_brick('switches')
        self.nwtopology = lookup_service_brick('topologydiscovery')
        self.datapaths = {}
        self.echo_latency = {}
        self.measure_thread = hub.spawn(self._calculator)
         
    def _calculator(self):
        """
	    Main function that triggers other function
	    1. It first calculates echo latency between switch and controller
	    2. Then it triggers function to send get latency calculated by LLDP packets
	    3. It triggers the function of latency calculation by using LLDP packets
        """
        while True:
            self._send_echo_request()
            self.save_link_latency()
            try:
		self.save_link_latency()
		self.display_latency()
            except:
	        self.nwtopology = lookup_service_brick('topologydiscovery')
            hub.sleep(constants.LATENCY_CALCULATION_PERIOD)

    def _send_echo_request(self):
        """
            This function sends echo request message to switches 
            This echo message is used to calculate echo latency between controller and switch
        """
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)
	    # sends echo request message within every 0.05 sec
            hub.sleep(0.05) 

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def get_echo_reply(self, ev):
        """
	    Fetch the time at which echo reply is received 
            This time is used to calculate echo delay between controller and switch
        """
        now_time = time.time()
        try:
            echo_latency = now_time - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = echo_latency
        except:
            return

    def _save_lldp_delay(self, src=0, dst=0, lldpdelay=0):
        try:
            self.nwtopology.database[src][dst]['lldpdelay'] = lldpdelay
        except:
            if self.nwtopology is None:
                self.nwtopology = lookup_service_brick('topologydiscovery')
            return

    def calculate_link_latency(self, src, dst):
        """ 
	   This is the function that calculates final latency of all links
           formula to calculate latency is:
	   latency = ((delay(A->B) - (echoA/2 + echoB/2)) + (delay(B->A) - (echoB/2 + echoA/2)))/2
        """
        try:
            latency_forward = self.nwtopology.database[src][dst]['lldpdelay']
            latency_backward = self.nwtopology.database[dst][src]['lldpdelay']
            src_echo_latency = self.echo_latency[src]
            dst_echo_latency = self.echo_latency[dst]
            latency  = (latency_forward + latency_backward - src_echo_latency - dst_echo_latency)/2
            return max(latency, 0)
        except:
            return float('inf')

    def save_link_latency(self):
        """
	    Calculate link latency and save it in network topology database
        """
        try:
            for src in self.nwtopology.database:
                for dst in self.nwtopology.database[src]:
                    if src == dst:
                        self.nwtopology.database[src][dst]['latency'] = 0
                        continue
                    latency = self.calculate_link_latency(src, dst)
                    self.nwtopology.database[src][dst]['latency'] = latency
        except Exception as ex:
            if self.nwtopology is None:
                self.nwtopology = lookup_service_brick('topologydiscovery')
            return

    def display_latency(self):
        if constants.SHOWLATENCY and self.nwtopology is not None and self.nwtopology.database.number_of_nodes()>0:
	    self.logger.info("\nsrc-dpid    dst-dpid               latency")
            self.logger.info("-----------------------------------------------")
            for src in self.nwtopology.database:
                for dst in self.nwtopology.database[src]:
                    latency = self.nwtopology.database[src][dst]['latency']
                    self.logger.info("%s<-->%s : %s" % (src, dst, latency))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _record_switches(self, ev):
        """     
        This function records the switch in main_dispatcher
        if the switch in MAIN_DISPATCHER is not already in database, then add it
        if the switch goes to DEAD_DISPATCHER then it isno longer active, remove it from database
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Adding OVS: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Removing OVS: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
            Parsing LLDP packet and get the delay of link.
        """
        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            dpid = msg.datapath.id
            if self.sw_module is None:
                self.sw_module = lookup_service_brick('switches')
            for port in self.sw_module.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    delay = self.sw_module.ports[port].delay
                    self._save_lldp_delay(src=src_dpid, dst=dpid,
                                          lldpdelay=delay)
        except LLDPPacket.LLDPUnknownFormat as e:
            return


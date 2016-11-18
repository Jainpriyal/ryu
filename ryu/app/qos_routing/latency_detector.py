"""
Calculate latency of all links


"""


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
        App to Calculate Latency of Links
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LatencyCalculator, self).__init__(*args, **kwargs)
        self.name = 'latency'
        self.sending_echo_request_interval = 0.05
        self.sw_module = lookup_service_brick('switches')
        self.topology = lookup_service_brick('topologydiscovery') ## use ryu method to get data from switches and topology

        self.datapaths = {}
        self.echo_latency = {}
        self.measure_thread = hub.spawn(self._calculator)

    def _calculator(self):
        """
	    This function will be called whenever ryu object gets instantiated
            This is the function that triggers other function to calculate latency
	    Operations:
	    1. send echo request
            2. Get time taken by LLDP packets from controller to switch
	    3. Measure link delay
	    It calculates link delay periodically, as given in LATENCY_CALCULATION_PERIOD
        """
        while True:
            self._send_echo_request()
            self.create_link_delay()
            try:
                self.topology.shortest_paths = {}
                self.logger.debug("Refresh the shortest_paths")
            except:
                self.topology = lookup_service_brick('topology')

            self.show_delay_statis()
            hub.sleep(constants.LATENCY_CALCULATION_PERIOD)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
	datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
		print "\n values:",self.datapaths.values()
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]


    def _send_echo_request(self):
        """
            Seng echo request msg to datapath.
        """
	if self.topology is None:
		self.topology = lookup_service_brick('topologydiscovery')
	print "\n ******** self.datapaths *********",self.topology
	for i in self.datapaths:
		print "\n datapaths:", i
        for datapath in self.datapaths:
            parser = datapath.ofproto_parser
            echo_req = parser.OFPEchoRequest(datapath,
                                             data="%.12f" % time.time())
            datapath.send_msg(echo_req)
            # Important! Don't send echo request together, Because it will
            # generate a lot of echo reply almost in the same time.
            # which will generate a lot of delay of waiting in queue
            # when processing echo reply in echo_reply_handler.

            hub.sleep(self.sending_echo_request_interval)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        """
            Handle the echo reply msg, and get the latency of link.
        """
        now_timestamp = time.time()
        try:
            latency = now_timestamp - eval(ev.msg.data)
            self.echo_latency[ev.msg.datapath.id] = latency
        except:
            return

    def get_delay(self, src, dst):
        """
            Get link delay.
                        Controller
                        |        |
        src echo latency|        |dst echo latency
                        |        |
                   SwitchA-------SwitchB
                        
                    fwd_delay--->
                        <----reply_delay
            delay = (forward delay + reply delay - src datapath's echo latency
        """
        try:
            fwd_delay = self.topology.database[src][dst]['lldpdelay']
            re_delay = self.topology.database[dst][src]['lldpdelay']
            src_latency = self.echo_latency[src]
            dst_latency = self.echo_latency[dst]
            
            delay = (fwd_delay + re_delay - src_latency - dst_latency)/2
            return max(delay, 0)
        except:
            return float('inf')

    def _save_lldp_delay(self, src=0, dst=0, lldpdelay=0):
        try:
            self.topology.database[src][dst]['lldpdelay'] = lldpdelay
        except:
            if self.topology is None:
                self.topology = lookup_service_brick('topology')
            return

    def create_link_delay(self):
        """
            Create link delay data, and save it into database object.
        """
        try:
            for src in self.topology.database:
                for dst in self.topology.database[src]:
                    if src == dst:
                        self.topology.database[src][dst]['delay'] = 0
                        continue
                    delay = self.get_delay(src, dst)
                    self.topology.database[src][dst]['delay'] = delay
        except:
            if self.topology is None:
                self.topology = lookup_service_brick('topology')
            return

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

    def show_delay_statis(self):
        if constants.DISPLAY and self.topology is not None:
            self.logger.info("\nsrc   dst      delay")
            self.logger.info("---------------------------")
            for src in self.topology.database:
                for dst in self.topology.database[src]:
                    delay = self.topology.database[src][dst]['delay']
                    self.logger.info("%s<-->%s : %s" % (src, dst, delay))

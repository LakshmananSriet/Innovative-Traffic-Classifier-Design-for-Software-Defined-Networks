from operator import attrgetter
from datetime import datetime
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class TrafficMonitor(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.switches = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_stats = {
            'timestamp': '',
            'datapath_id': '',
            'input_port': '',
            'source_mac': '',
            'destination_mac': '',
            'output_port': '',
            'packet_count': 0,
            'byte_count': 0
        }

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, event):
        datapath = event.datapath
        if event.state == MAIN_DISPATCHER:
            if datapath.id not in self.switches:
                self.logger.debug('Registering switch: %016x', datapath.id)
                self.switches[datapath.id] = datapath
        elif event.state == DEAD_DISPATCHER:
            if datapath.id in self.switches:
                self.logger.debug('Unregistering switch: %016x', datapath.id)
                del self.switches[datapath.id]

    def _monitor(self):
        self.logger.info('timestamp\tdatapath_id\tinput_port\tsource_mac\tdestination_mac\toutput_port\tpacket_count\tbyte_count')
        while True:
            for dp in self.switches.values():
                self._send_stats_request(dp)
            hub.sleep(1)

    def _send_stats_request(self, datapath):
        self.logger.debug('Sending stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_stats_request = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(flow_stats_request)

        port_stats_request = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(port_stats_request)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, event):
        body = event.msg.body

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.flow_stats['timestamp'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            self.flow_stats['datapath_id'] = event.msg.datapath.id
            self.flow_stats['input_port'] = stat.match['in_port']
            self.flow_stats['source_mac'] = stat.match['eth_src']
            self.flow_stats['destination_mac'] = stat.match['eth_dst']
            self.flow_stats['output_port'] = stat.instructions[0].actions[0].port
            self.flow_stats['packet_count'] = stat.packet_count
            self.flow_stats['byte_count'] = stat.byte_count

            self.logger.info('%s\t%x\t%d\t%s\t%s\t%d\t%d\t%d',
                             self.flow_stats['timestamp'],
                             self.flow_stats['datapath_id'],
                             self.flow_stats['input_port'],
                             self.flow_stats['source_mac'],
                             self.flow_stats['destination_mac'],
                             self.flow_stats['output_port'],
                             self.flow_stats['packet_count'],
                             self.flow_stats['byte_count'])

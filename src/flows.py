import csv
from collections import OrderedDict

import single_flow
import single_packet 
import hash

class Flows:
    def __init__(self):
        # Python dictionaries to hold current and archived & filtered flow records:
        self.flow_cache = OrderedDict()
        self.flow_archive = OrderedDict()
        self.flow_filtered = OrderedDict()

        self.flow = single_flow.Flow(self.flow_cache, self.flow_archive)
        self.packets_ignored = 0
        self.packets_processed = 0

    def add_packet(self, dpkt_reader):
        for timestamp, packet in dpkt_reader:
            packet = single_packet.Packet(timestamp, packet)
            if packet.ingested:
                # Update the flow with packet info:
                self.flow.update_flows(packet)
                self.packets_processed += 1
            else:
                self.packets_ignored += 1

    def filter_packets(self):

        packets_size_avg = []
        flows_duration_avg = []
        flows_count_avg = []
        flows_counts = OrderedDict()

        # add flows that are in flow_cache
        self.flow_archive.update(self.flow_cache);
        self.flow_cache.clear()

        for flow_dict in self.flow_archive.items():
            packets_size_avg.append(flow_dict[1]['packets_sizes']) 
            flows_duration_avg.append(flow_dict[1]['flowDuration'])

            # calculate flows count
            flow_hash = hash.hash_b3((flow_dict[1]['src_ip'], flow_dict[1]['dst_ip'], flow_dict[1]['proto']))
            if flow_hash in flows_counts: 
                flows_counts[flow_hash] += 1
            else:
                flows_counts[flow_hash] = 1 

        for flow in flows_counts.items():
            flows_count_avg.append(flow[1])
        
        flow_size_threshold = sum(packets_size_avg) / len(packets_size_avg)
        flow_duration_threshold = sum(flows_duration_avg) / len(flows_duration_avg)
        flows_count_threshold = sum(flows_count_avg) // len(flows_count_avg)

        #  filter flows that is rare
        result = OrderedDict()
        for flow in flows_counts.items():
            if flow[1] >= flows_count_threshold:
                result[flow[0]] = flow[1]
        
        flows_counts = result;

        result = OrderedDict()
        for flow_dict in self.flow_archive.items():

            """
            add all flows that are in flows_counts
            flows_count has the flows that is satisfied the
            flow counts requirements(or flows that is not rare)
            
            also add flows that is not huge in size
            
            also add flows that is not long in time
            """
            flow_hash = hash.hash_b3((flow_dict[1]['src_ip'], flow_dict[1]['dst_ip'], flow_dict[1]['proto']))
            if flow_dict[1]['packets_sizes'] <= flow_size_threshold and flow_dict[1]['flowDuration'] <= flow_duration_threshold and \
                flow_hash in flows_counts:
                result[flow_dict[0]] = flow_dict[1];

        self.flow_filtered = result

    def write_csv(self, file_name):
        """
        Write all flow records out to CSV file
        """
        with open(file_name, mode='w') as csv_file:
            fieldnames = ['src_ip', 'src_port', 'dst_ip', 'dst_port',
                          'proto', 'all_flags', 'packets_count', 'packets_sizes',
                          'flowStart', 'flowEnd', 'flowDuration',
                         ]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for flow_dict in self.flow_filtered.items():
                writer.writerow(flow_dict[1])
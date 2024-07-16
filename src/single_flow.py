import hash
import single_packet

class Flow:
    def __init__(self, flow_cache, flow_archive):
        self.flow_cache = flow_cache
        self.flow_archive = flow_archive
        # Threshold time in seconds between packets with same flow keys
        # whereby will be considered a new separate flow:
        self.flow_expiration = 0.5

    def update_flows(self, packet):
        """
        implement separate logic for UDP & TCP
        because TCP has flags
        """
        if packet.proto == 6:
            # TCP
            if packet.flow_hash in self.flow_cache:
                flow_hash = packet.flow_hash
                flow_dict = self.flow_cache[flow_hash]
                if self.is_flow_fresh(packet, self.flow_cache[packet.flow_hash]):
                    # if SYN flag has been set before and current packet has SYN_ACK flag
                    last_packet_flags = self.flow_cache[packet.flow_hash]['all_flags'][-1]
                    if single_packet.Packet.has_syn_ack_flag(packet.tp_flags) and self.packet_direction(packet, flow_dict) == 'b' and \
                       single_packet.Packet.has_syn_flag(last_packet_flags):
                        self._updated_founded_flow(packet)

                    # if SYN_ACK flag has been set before and current packet has ACK flag
                    elif single_packet.Packet.has_ack_flag(packet.tp_flags) and single_packet.Packet.has_syn_ack_flag(last_packet_flags) and \
                         self.packet_direction(packet, flow_dict) == 'f':
                        self._updated_founded_flow(packet);

                    # if ACK flag has been set before and current packet has FIN flag
                    elif single_packet.Packet.has_fin_flag(packet.tp_flags) and single_packet.Packet.has_ack_flag(last_packet_flags) and \
                        self.packet_direction(packet, flow_dict) == 'f' or \
                        single_packet.Packet.has_fin_flag(packet.tp_flags) and single_packet.Packet._has_3way_connection(flow_dict['all_flags']) and self.packet_direction(packet, flow_dict) == 'f':
                        # if FIN flag has been set and we have 3-way connection
                        self._updated_founded_flow(packet);

                    # if FIN flag has been set before (with 3way_connection before it) and current packet has ACK flag
                    elif single_packet.Packet.has_ack_flag(packet.tp_flags) and single_packet.Packet.has_fin_flag(last_packet_flags) and \
                        single_packet.Packet._has_3way_connection(flow_dict['all_flags']) and self.packet_direction(packet, flow_dict) == 'b':
                        self._updated_founded_flow(packet)

                    # if ACK flag has been set before and current packet has FIN flag
                    elif single_packet.Packet.has_fin_flag(packet.tp_flags) and single_packet.Packet.has_ack_flag(last_packet_flags) and \
                        single_packet.Packet._has_3way_connection(flow_dict['all_flags']) and self.packet_direction(packet, flow_dict) == 'b':
                        self._updated_founded_flow(packet)

                    # if FIN flag has been set before and current packet has ACK flag
                    # BACKUP: elif packet.has_ack_flag() and last_packet_flags.has_fin_flag() and \
                    elif single_packet.Packet.has_ack_flag(packet.tp_flags) and single_packet.Packet.has_fin_flag(last_packet_flags) and \
                        single_packet.Packet._has_3way_connection(flow_dict['all_flags']) and self.packet_direction(packet, flow_dict) == 'f':
                        # connection closed, flow should be archived
                        self._archive_flow(packet)
                        # Delete from dict:
                        self.flow_cache.pop(packet.flow_hash, None)
                
                    # if current packet has RST flag & we had tcp connection before
                    elif single_packet.Packet.has_rst_flag(packet.tp_flags) and single_packet.Packet._has_3way_connection(flow_dict['all_flags']):
                        # connection closed, flow should be archived
                        self._archive_flow(packet)
                        # Delete from dict:
                        self.flow_cache.pop(packet.flow_hash, None)
                    # if non of this packet, then create new flow
                    else:
                        self._create_new_flow(packet)

                else:
                    """
                    if flow was expired, we sure that it is a incomplete connection
                    because we handle all conditions in previous condition
                    so we delete flow because we don't want incomplete connection
                    """
                    self.flow_cache.pop(packet.flow_hash, None)
            else:
                if single_packet.Packet.has_syn_flag(packet.tp_flags):
                    self._create_new_flow(packet)
                else:
                    pass
                    # ignore it

        # UDP
        elif packet.proto == 17:
            """
            Add or update flow in in flow_cache dictionary
            """
            if packet.flow_hash in self.flow_cache:
                # Found existing flow in dict, update it:
                if self.is_flow_fresh(packet, self.flow_cache[packet.flow_hash]):
                    # Update standard flow parameters:
                    self._updated_founded_flow(packet)
                else:
                    # Expired flow so archive it:
                    self._archive_flow(packet)
                    # Delete from dict:
                    self.flow_cache.pop(packet.flow_hash, None)
                    # Now create as a new flow based on current packet:
                    self._create_new_flow(packet)
            else:
                self._create_new_flow(packet)
        else:
            pass


    def _updated_founded_flow(self, packet):
        # update existing flow in flow_cache dictionary 
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        # Update the count of packets and octets:
        flow_dict['packets_count'] += 1
        flow_dict['packets_sizes'] += packet.length
        flow_dict['all_flags'].append(packet.tp_flags)
        # Store the timestamps of the newly captured packet:
        flow_dict['times'].append(packet.timestamp)
        # As we have now at least 2 packets in the flow, we can calculate the packet-inter-arrival-time.
        flow_dict['listOfDelays'].append(flow_dict['times'][-1] \
            - flow_dict['times'][-2])
        # Update the flow end/duration (the start does not change)
        flow_dict['flowEnd'] = packet.timestamp
        flow_dict['flowDuration'] = (packet.timestamp - flow_dict['flowStart'])

    def _create_new_flow(self, packet):
        """
        Create new flow in flow_cache dictionary
        """
        flow_hash = packet.flow_hash
        # Create new key etc in flow dict for this flow:
        # Initialise the new flow key:
        self.flow_cache[flow_hash] = {}
        flow_dict = self.flow_cache[flow_hash]

        flow_dict['src_ip'] = packet.ip_src
        flow_dict['dst_ip'] = packet.ip_dst
        flow_dict['proto'] = packet.proto
        flow_dict['src_port'] = packet.tp_src
        flow_dict['dst_port'] = packet.tp_dst
        flow_dict['all_flags'] = []
        flow_dict['all_flags'].append(packet.tp_flags)
        flow_dict['packets_count'] = 1
        flow_dict['packets_sizes'] = packet.length
        flow_dict['times'] = []
        flow_dict['times'].append(packet.timestamp)
        flow_dict['listOfDelays'] = []
        flow_dict['flowStart'] = packet.timestamp
        flow_dict['flowEnd'] = packet.timestamp
        flow_dict['flowDuration'] = 0

    def is_flow_fresh(self, packet, flow_dict):
        """
        check if flow is current or has expired.
        only check if the flow hash is already known
        in flow is greater than flow expiration threshold
        """
        if flow_dict['listOfDelays']:
            if (packet.timestamp - flow_dict['times'][-1]) > self.flow_expiration:
                # Flow has expired:
                return False
            else:
                # Flow has not expired:
                return True
        elif flow_dict['packets_count'] == 1:
            # Was only 1 packet so check current packet with only packet exists
            if (packet.timestamp - flow_dict['flowStart']) > self.flow_expiration:
                # Flow has expired:
                return False
            else:
                # Flow has not expired:
                return True
        else:
            # no packet?
            return True

    def _archive_flow(self, packet):
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        flow_start_time = flow_dict['flowStart']
        ip_src = flow_dict['src_ip']
        ip_dst = flow_dict['dst_ip']
        proto = flow_dict['proto']
        tp_src = flow_dict['src_port']
        tp_dst = flow_dict['dst_port']
        # Create new more hash key for archiving with start of flow time(flowStart)
        if proto == 6 or proto == 17:
            # Generate a directional 6-tuple flow_hash:
            new_hash = hash.hash_b6((ip_src,
                                    ip_dst, proto, tp_src,
                                    tp_dst, flow_start_time))
        else:
            pass
            # ignore all other type of packets

        # Check key isn't already used in archive:
        if new_hash in self.flow_archive:
            print("archive duplicate flow key", new_hash)
            return

        self.flow_archive[new_hash] = flow_dict

    def packet_direction(self, packet, flow_dict):
        """
        Determine packet direction (f=forward, r=reverse)
        """
        if packet.ip_src == flow_dict['src_ip']:
            return 'f'
        elif packet.ip_src == flow_dict['dst_ip']:
            return 'b'
        else:
            print("something went wrong")
            return
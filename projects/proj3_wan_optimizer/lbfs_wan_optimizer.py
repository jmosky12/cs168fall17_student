import wan_optimizer
import utils
import tcp_packet

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        self.buffers = {}
        self.hash_payloads = {}
        self.sliding_window = ""
        # Add any code that you like here (but do not add any constructor arguments).
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        packet_key = (packet.src, packet.dest)
        # receiving wan
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.

            # if hash code, just send the corresponding block immediately
            if not packet.is_raw_data:
                block = self.hash_payloads[packet.payload]
                self.send_block(block, packet_key, packet.is_fin, False)
            # otherwise, buffer for full 8k bytes
            else:
                self.add_packet_to_buffer(packet_key, packet)
                curr_block = self.buffers[packet_key]
                block_length = len(curr_block)
                # see if block reaches 8000 byte goal
                left = 0
                right = 48 if block_length >= 48 else block_length
                while right <= block_length:
                    block = curr_block[left:right]
                    block_hash = utils.get_hash(block)
                    is_delimiter = utils.get_last_n_bits(block_hash, 13) == self.GLOBAL_MATCH_BITSTRING
                    if is_delimiter:
                        send_block = curr_block[:right]
                        curr_block = curr_block[right:]
                        self.buffers[packet_key] = curr_block
                        self.determine_if_hashed(send_block, packet_key, packet.is_fin, False)
                        left = right
                        if block_length - right >= 48:
                            right = right + 48
                        else:
                            right = block_length
                            if packet.is_fin:
                                send_block = curr_block[left: block_length]
                                self.determine_if_hashed(send_block, packet_key, True, False)
                                self.buffers.pop(packet_key, None)
                            break
                    else:
                        left = left + 1
                        right = right + 1

                if packet_key in self.buffers:
                    if packet.is_fin:
                        send_block = self.buffers[packet_key]
                        self.determine_if_hashed(send_block, packet_key, True, False)
                        self.buffers.pop(packet_key, None)
                else:
                    self.buffers.pop(packet_key, None)
        # sending wan
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.

            # add packet to buffer based on (src, dest)
            self.add_packet_to_buffer(packet_key, packet)
            curr_block = self.buffers[packet_key]
            block_length = len(curr_block)
            left = 0
            right = 48 if block_length >= 48 else block_length
            while right <= block_length:
                block = curr_block[left:right]
                block_hash = utils.get_hash(block)
                is_delimiter = utils.get_last_n_bits(block_hash, 13) == self.GLOBAL_MATCH_BITSTRING
                if is_delimiter:
                    send_block = curr_block[:right]
                    curr_block = curr_block[right:]
                    self.buffers[packet_key] = curr_block
                    self.determine_if_hashed(send_block, packet_key, packet.is_fin, True)
                    left = right
                    if block_length - right >= 48:
                        right = right + 48
                    else:
                        right = block_length
                        if packet.is_fin:
                            send_block = curr_block[left: block_length]
                            self.determine_if_hashed(send_block, packet_key, True, True)
                            self.buffers.pop(packet_key, None)
                        break
                else:
                    left = left + 1
                    right = right + 1
            if packet_key in self.buffers:
                if packet.is_fin:
                    send_block = self.buffers[packet_key]
                    self.determine_if_hashed(send_block, packet_key, True, True)
                    self.buffers.pop(packet_key, None)
            else:
                self.buffers.pop(packet_key, None)

    # add new packet to appropriate (src, dest) buffer
    def add_packet_to_buffer(self, packet_key, packet):
        if packet_key in self.buffers:
            self.buffers[packet_key] += packet.payload
        else:
            self.buffers[packet_key] = packet.payload

    # add block to hash-->block mappings
    def add_block_to_hashes(self, block):
        hash_code = utils.get_hash(block)
        self.hash_payloads[hash_code] = block

    # if previously hashed, send the hash. else add block to hashes and then send out block
    def determine_if_hashed(self, block, packet_key, is_fin, is_remote):
        hash_code = utils.get_hash(block)
        if hash_code in self.hash_payloads:
            self.send_hash(hash_code, packet_key, is_fin, is_remote)
        else:
            self.add_block_to_hashes(block)
            self.send_block(block, packet_key, is_fin, is_remote)

    def send_hash(self, hash_code, packet_key, is_fin, is_remote):
        packet = tcp_packet.Packet(packet_key[0], packet_key[1], False, is_fin, hash_code)
        if is_remote:
            self.send(packet, self.wan_port)
        else:
            self.send(packet, self.address_to_port[packet_key[1]])

    def send_block(self, block, packet_key, is_fin, is_remote):
        length = len(block)
        i = 0
        packets = []
        while length > 1500:
            packet = tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[i:i+1500])
            packets.append(packet)
            length = length - 1500
            i = i + 1500
        packets.append(tcp_packet.Packet(packet_key[0], packet_key[1], True, is_fin, block[i:i+length]))
        for packet in packets:
            if is_remote:
                self.send(packet, self.wan_port)
            else:
                self.send(packet, self.address_to_port[packet_key[1]])


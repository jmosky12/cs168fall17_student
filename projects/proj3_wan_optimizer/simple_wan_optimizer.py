import wan_optimizer
import utils
import tcp_packet

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        self.buffers = {}
        self.hash_payloads = {}
        # Add any code that you like here (but do not add any constructor arguments).
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
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
                length = len(block)
                if length < 8000:
                    self.send_partial_block(block, packet_key, False)
                else:
                    self.send_full_block(block, packet_key, packet.is_fin, False)
            # otherwise, buffer for full 8k bytes
            else:
                # add packet to buffer based on (src, dest)
                self.add_packet_to_buffer(packet_key, packet)
                curr_block = self.buffers[packet_key]
                block_length = len(curr_block)
                has_remainder = len(curr_block) > 8000
                # see if block reaches 8000 byte goal
                if block_length >= 8000:
                    block = curr_block[:8000]
                    if has_remainder:
                        remainder = curr_block[8000:]
                        self.buffers[packet_key] = remainder
                        # fin packet splits into new buffer, so send it
                        if packet.is_fin:
                            # send out remainder fin packet
                            self.determine_if_hashed(remainder, packet_key, True, False, True)
                            self.buffers.pop(packet_key, None)
                    else:
                        self.buffers.pop(packet_key, None)
                    # send out full packet
                    self.determine_if_hashed(block, packet_key, packet.is_fin, False, False)
                elif packet.is_fin:
                    # send out <8000 byte block that contains fin
                    self.determine_if_hashed(curr_block, packet_key, True, False, True)
                    self.buffers.pop(packet_key, None)
        # sending wan
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.

            # add packet to buffer based on (src, dest)
            self.add_packet_to_buffer(packet_key, packet)
            curr_block = self.buffers[packet_key]
            block_length = len(curr_block)
            has_remainder = len(curr_block) > 8000
            # see if block reaches 8000 byte goal
            if block_length >= 8000:
                block = curr_block[:8000]
                if has_remainder:
                    remainder = curr_block[8000:]
                    self.buffers[packet_key] = remainder
                    # fin packet splits into new buffer, so send it
                    if packet.is_fin:
                        # send out remainder fin packet
                        self.determine_if_hashed(remainder, packet_key, True, True, True)
                        self.buffers.pop(packet_key, None)
                else:
                    self.buffers.pop(packet_key, None)
                # send out full packet
                self.determine_if_hashed(block, packet_key, packet.is_fin, True, False)
            elif packet.is_fin:
                # send out <8000 byte block that contains fin
                self.determine_if_hashed(curr_block, packet_key, True, True, True)
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
    def determine_if_hashed(self, block, packet_key, is_fin, is_remote, is_partial):
        hash_code = utils.get_hash(block)
        if hash_code in self.hash_payloads:
            self.send_hash(hash_code, packet_key, is_fin, is_remote)
        else:
            self.add_block_to_hashes(block)
            if is_partial:
                self.send_partial_block(block, packet_key, is_remote)
            else:
                self.send_full_block(block, packet_key, is_fin, is_remote)

    def send_hash(self, hash_code, packet_key, is_fin, is_remote):
        packet = tcp_packet.Packet(packet_key[0], packet_key[1], False, is_fin, hash_code)
        if is_remote:
            self.send(packet, self.wan_port)
        else:
            self.send(packet, self.address_to_port[packet_key[1]])

    def send_full_block(self, block, packet_key, is_fin, is_remote):
        packets = [tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[:1500]),
            tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[1500:3000]),
            tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[3000:4500]),
            tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[4500:6000]),
            tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[6000:7500]),
            tcp_packet.Packet(packet_key[0], packet_key[1], True, is_fin, block[7500:])
        ]
        if is_remote:
            for packet in packets:
                self.send(packet, self.wan_port)
        else:
            for packet in packets:
                self.send(packet, self.address_to_port[packet_key[1]])

    def send_partial_block(self, block, packet_key, is_remote):
        length = len(block)
        packets = []
        for i in range(1500, 9000, 1500):
            if length < i:
                packets.append(tcp_packet.Packet(packet_key[0], packet_key[1], True, True, block[i-1500:length]))
                break
            else:
                packets.append(tcp_packet.Packet(packet_key[0], packet_key[1], True, False, block[i-1500:i]))
        if is_remote:
            for packet in packets:
                self.send(packet, self.wan_port)
        else:
            for packet in packets:
                self.send(packet, self.address_to_port[packet_key[1]])

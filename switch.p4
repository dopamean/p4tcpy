/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> tcpPort_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    tcpPort_t srcPort;
    tcpPort_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3> reserved;
    bit<3> ecn;
    bit<6> flags;
    bit<16> windowSize;
    bit<16> checkSum;
    bit<16> urgentPtr;
}

header tcp_option_end_t {
    bit<8> kind;
}

header tcp_option_noop_t {
    bit<8> kind;
}

header tcp_option_mss_t {
    bit<8> kind;
    bit<8> option_size;
    bit<16> segment_size;
}

header tcp_option_ws_t {
    bit<8> kind;
    bit<8> option_size;
    bit<8> windows_scale;
}

header tcp_option_SACKOK_t {
    bit<8> kind;
    bit<8> option_size;
}

header tcp_option_SACK_t {
    bit<8> kind;
    bit<8> option_size;
    varbit<256> blocks;
}

header tcp_option_timestamp_t {
    bit<8> kind;
    bit<8> option_size;
    bit<32> timestamp;
    bit<32> echo;
}

struct tcp_option_SACK_header {
    bit<8> kind;
    bit<8> option_size;
}

header_union tcp_option_t {
    tcp_option_end_t end;
    tcp_option_noop_t noop;
    tcp_option_mss_t mss;
    tcp_option_ws_t ws;
    tcp_option_SACKOK_t SACKOK;
    tcp_option_SACK_t SACK;
    tcp_option_timestamp_t timestamp;
}

typedef tcp_option_t[10] tcp_options_t;

header tcp_option_padding_t {
    varbit<256> padding;
}

struct metadata {
    bit<16> packet_length;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    tcp_t                tcp;
    tcp_options_t        tcp_options;
    tcp_option_padding_t tcp_padding;
}

enum bit<6> TCP_flags {
    FIN = 0x001,
    SYN = 0x002,
    RST = 0x004,
    PSH = 0x008,
    ACK = 0x010,
    URG = 0x020
    //ECN = 0x040,
    //CWR = 0x080,
    //NON = 0x100
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser TCP_options_parser(packet_in packet,
                          in bit<4> tcp_header_data_offset,
                          out tcp_options_t tcp_options,
                          out tcp_option_padding_t tcp_options_padding) {

    // Based on https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4
    // and https://en.wikipedia.org/wiki/Transmission_Control_Protocol

    bit<7> tcp_header_bytes_left;

    state start {
        tcp_header_bytes_left = 4 * (bit<7>)(tcp_header_data_offset - 5);
        transition next_option;
    }

    state next_option {
        transition select(tcp_header_bytes_left){
            0: accept;
            default: next_option2;
        }
    }

    state next_option2 {
        transition select(packet.lookahead<bit<8>>()) {
            0: option_end;
            1: option_noop;
            2: option_mss;
            3: option_ws;
            4: option_SACKOK;
            5: option_SACK;
            8: option_timestamp;
        }
    }

    state consume_all {
        // Extract everything as padding to the end of the options buffer...
        // If the incoming packet had an error in it's TCP options we'll be progating that error.
        packet.extract(tcp_options_padding, (bit<32>)(8 * (bit<9>)tcp_header_bytes_left));
        transition accept;
    }

    state option_end {
        packet.extract(tcp_options.next.end);
        tcp_header_bytes_left = tcp_header_bytes_left - 1;
        transition consume_all;
    }

    state option_noop {
        packet.extract(tcp_options.next.noop);
        tcp_header_bytes_left = tcp_header_bytes_left - 1;
        transition next_option;
    }

    state option_mss {
        packet.extract(tcp_options.next.mss);
        tcp_header_bytes_left = tcp_header_bytes_left - 5;
        transition next_option;
    }

    state option_ws {
        packet.extract(tcp_options.next.ws);
        tcp_header_bytes_left = tcp_header_bytes_left - 3;
        transition next_option;
    }

    state option_SACKOK {
        packet.extract(tcp_options.next.SACKOK);
        tcp_header_bytes_left = tcp_header_bytes_left - 2;
        transition next_option;
    }

    state option_SACK {
        bit<8> sack_bytes = packet.lookahead<tcp_option_SACK_header>().option_size;
        tcp_header_bytes_left = tcp_header_bytes_left - (bit<7>)sack_bytes;
        packet.extract(tcp_options.next.SACK, (bit<32>)(8 * sack_bytes - 16));
        transition next_option;
    }

    state option_timestamp {
        packet.extract(tcp_options.next.timestamp);
        tcp_header_bytes_left = tcp_header_bytes_left - 10;
        transition next_option;
    }

}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
        // For this thech demo we won't be carig about non-ethernet traffic.
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x06: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        TCP_options_parser.apply(packet, hdr.tcp.dataOffset, hdr.tcp_options, hdr.tcp_padding);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (hdr.tcp.isValid()) {
            // Return packet on source port.
            standard_metadata.egress_spec = standard_metadata.ingress_port;

            meta.packet_length = hdr.ipv4.totalLen - 0x5;

            // Fake ethernet answer.
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = 0x0C001B00B135;

            // Fake IP answer.
            ip4Addr_t IP_dest;
            IP_dest = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = IP_dest;

            hdr.ipv4.totalLen = hdr.ipv4.minSizeInBytes() + hdr.tcp.minSizeInBytes(); // BC, we're truncating the packet in the egress...

            // Fake TCP answer.
            tcpPort_t TCP_dest_port;
            TCP_dest_port = hdr.tcp.dstPort;
            hdr.tcp.dstPort = hdr.tcp.srcPort;
            hdr.tcp.srcPort = TCP_dest_port;
            hdr.tcp.dataOffset = 0x5;
            hdr.tcp.windowSize = 0x0;

            bit<32> last_seq_num = hdr.tcp.seqNo;
            //TODO: Seq number
            hdr.tcp.seqNo = hdr.tcp.seqNo;


            bit<6> new_flags = 0x0;

            //TODO: more flags

            // SYN > SYN,ACK
            if (hdr.tcp.flags == TCP_flags.SYN) {
                new_flags = TCP_flags.SYN ^ TCP_flags.ACK;

            }
/*
            // ACK > Increase sequence number
            if (hdr.tcp.flags & TCP_flags.ACK == TCP_flags.ACK) {
                hdr.tcp.seqNo = hdr.tcp.ackNo;
            }
*/
            // Finished parsing incoming flags..
            hdr.tcp.flags = new_flags;
/*
            // Seat a random sequence number if SYN was set
            if (hdr.tcp.flags & TCP_flags.SYN == TCP_flags.SYN) {
                hdr.tcp.seqNo = 0x01; // Much random, such security
                //hdr.tcp.seqNo = 0x01 + ((bit<32>) hdr.tcp.windowSize); // Much random, such security
            }
*/
            // Set ack number if outbound ACK was set.
            if (hdr.tcp.flags & TCP_flags.ACK == TCP_flags.ACK) {
                hdr.tcp.ackNo = last_seq_num + 1;
            }

        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        truncate(hdr.ethernet.minSizeInBytes() + hdr.ipv4.minSizeInBytes() + hdr.tcp.minSizeInBytes());
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
         update_checksum(
             hdr.ipv4.isValid(),
             {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.packet_length,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.ecn,
                hdr.tcp.flags,
                hdr.tcp.windowSize,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checkSum,
            HashAlgorithm.csum16
        );

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

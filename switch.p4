/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

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
    bit<12> flags;
    bit<16> windowSize;
    bit<16> checkSum;
    bit<16> urgentPtr;
//    bit<50> options; //We won't be doing options...
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

enum bit<12> TCP_flags {
    FIN = 0x001,
    SYN = 0x002,
    RST = 0x004,
    PSH = 0x008,
    ACK = 0x010,
    URG = 0x020,
    ECN = 0x040,
    CWR = 0x080,
    NON = 0x100
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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

            // Fake ethernet answer.
            macAddr_t eth_dest;
            eth_dest = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = eth_dest;

            // Fake IP answer.
            ip4Addr_t IP_dest;
            IP_dest = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = IP_dest;

            // Fake TCP answer.
            tcpPort_t TCP_dest_port;
            TCP_dest_port = hdr.tcp.dstPort;
            hdr.tcp.dstPort = hdr.tcp.srcPort;
            hdr.tcp.srcPort = TCP_dest_port;

            bit<32> last_seq_num = hdr.tcp.seqNo;
            //TODO: Seq number
            //hdr.tcp.seqNo = hdr.tcp.seqNo + 1;


            //TODO: more flags

            // SYN > SYN,ACK
            if (hdr.tcp.flags == TCP_flags.SYN) {
                hdr.tcp.flags = TCP_flags.SYN ^ TCP_flags.ACK;
            }

            // Set ack number if ACK was set.
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

    action send_back_acknowledgement(bit<50> payloadMsg) {
        hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
        hdr.tcp.seqNo = 666999;
        bit<48> tmp;
        tmp = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr =  hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp;


        bit<16> tmpPort;
        tmpPort = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = tmpPort;

        //hdr.tcp.msg = payloadMsg;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table response {
        key = {
            hdr.tcp.flags   : exact;
        }

        actions = {
            send_back_acknowledgement;
            /* process_segment; */
            drop;
        }

        const default_action = drop();
    }




    apply {
        /*
        if (hdr.tcp.isValid()) {
            response.apply();
        } else {
            drop();
        }
        */
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
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

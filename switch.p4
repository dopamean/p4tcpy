/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
// nincsen type
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
    bit<4> dataOffset;   // 20 byte minimum  max 60byte
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
    bit<8> kind;           // tcp type
    bit<8> option_size;
    bit<16> segment_size;  //
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

parser TCP_options_parser(packet_in packet,   //█▓▒░ 6      OPCIONális részek csak
                          in bit<4> tcp_header_data_offset,
                          out tcp_options_t tcp_options,
                          out tcp_option_padding_t tcp_options_padding) {
        //█▓▒░ teljes 32 bitre kell ki paddingelni az END opció után
                //   ha üres az option .... akkor nincsen END opciója

    // Based on https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4
    // and https://en.wikipedia.org/wiki/Transmission_Control_Protocol

    bit<7> tcp_header_bytes_left;

    state start {    //█▓▒░ 6.1
        tcp_header_bytes_left = 4 * (bit<7>)(tcp_header_data_offset - 5);// bit 7 re konvertált a példa doksi
            ////█▓▒░
        transition next_option;
    }

    state next_option {   //█▓▒░ 6.2
        transition select(tcp_header_bytes_left){
            0: accept;
            default: next_option2;     ////█▓▒░6.3 LOOP
        }
    }

    state next_option2 {
        transition select(packet.lookahead<bit<8>>()) {  // (KIND= tcp opció típusa) nem parsoljuk fel hanem csak kiolvassuk
            0: option_end;  // tcp opcionélis adattagokat másmás adatot tartalmaznak és azt kell feldolgozni
            1: option_noop; // loop
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
        tcp_header_bytes_left = tcp_header_bytes_left - 1; //
        transition consume_all; //    KILÉP a parsebol
    }

    state option_noop {
        packet.extract(tcp_options.next.noop);
        tcp_header_bytes_left = tcp_header_bytes_left - 1;
        transition next_option;    /// LOOP
    }

    state option_mss {
        packet.extract(tcp_options.next.mss);
        tcp_header_bytes_left = tcp_header_bytes_left - 5;  // itt 5 byte méretű az opció
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

parser MyParser(packet_in packet,                     //█▓▒░  1
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {   //█▓▒░2
        transition parse_ethernet;
        // For this thech demo we won't be carig about non-ethernet traffic.
    }

    state parse_ethernet {  //█▓▒░3 ethernet parse
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {   //█▓▒░ 4 ip 4 parse
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x06: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {   //█▓▒░ 5   // tcp parse
        packet.extract(hdr.tcp);   ////█▓▒░ teljes tcp-t kiolvassuk
                ////█▓▒░ tcp data offset = teljes tcp = kötelező + opcionális  (sima size )
        TCP_options_parser.apply(packet, hdr.tcp.dataOffset, hdr.tcp_options, hdr.tcp_padding);
        transition accept;  //█▓▒░ 8
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }   //█▓▒░  9 drop if not correct
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,                      //█▓▒░ 10
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {                          //█▓▒░ 10.1
        if (hdr.tcp.isValid()) {
            // Return packet on source port.
            standard_metadata.egress_spec = standard_metadata.ingress_port;  //█▓▒░ bemenetre kimenet

            meta.packet_length = hdr.ipv4.totalLen - 0x5 - 0x30 + 0x13 -0x6; //0x100;
            meta.packet_length = 0x14; //20 byte  //hdr.ipv4.totalLen - 0x28; // ░ mert 40 bit hosszúságot le kell vonni hogy csak a TCP-t kapjuk meg
                                                                // █ kell egy new variable ami a tcp_length- nevet kapja ... de amig a meta-t máshol nem hazsnáljuk addig biztonságos
            // Fake ethernet answer.
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = 0x0C001B00B135;        //  égetett kamu szám ezért kell egy ilyen

            // Fake IP answer.
            ip4Addr_t IP_dest;
            IP_dest = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = IP_dest;
            bit<16> last_total_Len  = hdr.ipv4.totalLen;
            hdr.ipv4.totalLen = hdr.ipv4.minSizeInBytes() + hdr.tcp.minSizeInBytes(); // BC, we're truncating the packet in the egress...

            // Fake TCP answer.
            tcpPort_t TCP_dest_port;
            TCP_dest_port = hdr.tcp.dstPort;
            hdr.tcp.dstPort = hdr.tcp.srcPort;
            hdr.tcp.srcPort = TCP_dest_port;
            hdr.tcp.dataOffset = 0x5;
            hdr.tcp.windowSize = 0xA564;
                // █ 0x0 volt a példa 42340  = 0xA564 // !!!  ellenörizni

            bit<32> last_seq_num = hdr.tcp.seqNo;
            //TODO: Seq number
                /*
                    az aktuális küldő fél egyedi seqNo ... a packet
                */
            hdr.tcp.seqNo = 0x8BD3370;  // █ 8BD3370 nagyon egyedi        hdr.tcp.seqNo = hdr.tcp.seqNo;


            bit<6> new_flags = 0x0;

            //TODO: more flags

            // SYN > SYN,ACK
            if (hdr.tcp.flags == TCP_flags.SYN) {      //█▓▒░  is_hand_1
                new_flags = TCP_flags.SYN ^ TCP_flags.ACK; // kalap = XOR és az enumban binárisan benne van a két 1 es
                hdr.tcp.flags = new_flags;
                // Set ack number if outbound ACK was set.
                if (hdr.tcp.flags & TCP_flags.ACK == TCP_flags.ACK) {
                    hdr.tcp.ackNo = last_seq_num + 1;
                }
            }
            else if (hdr.tcp.flags ==  0x018)  // TCP_flags.PSH ^ TCP_flags.ACK
            {      //█▓▒░  sima msg ...
                new_flags = TCP_flags.ACK; // kalap = XOR és az enumban binárisan benne van a két 1 es
                meta.packet_length = hdr.ipv4.totalLen -  0x14;  //    meta.packet_length =  0xA0;  // 160 bit azaz 20 byte a tcp fejléce + payload De itt ez nincsen
                hdr.tcp.seqNo = hdr.tcp.ackNo;
                hdr.tcp.ackNo = (bit<32>) ((bit<32>)(last_total_Len- 0x14 -0x14) + (bit<32>)last_seq_num );  //

            }
            else if (hdr.tcp.flags ==  TCP_flags.FIN || (hdr.tcp.flags ==  TCP_flags.FIN ^ TCP_flags.ACK ) )  // TCP_flags.PSH ^ TCP_flags.ACK
            {      //█▓▒░  sima msg ...
                new_flags = TCP_flags.ACK ^ TCP_flags.FIN; // kalap = XOR és az enumban binárisan benne van a két 1 es

                meta.packet_length = hdr.ipv4.totalLen -  0x14;  //    meta.packet_length =  0xA0;  // 160 bit azaz 20 byte a tcp fejléce + payload De itt ez nincsen
                //hdr.tcp.seqNo = hdr.tcp.ackNo;
                //hdr.tcp.ackNo = (bit<32>) ((bit<32>)(last_total_Len- 0x14 -0x14) + (bit<32>)last_seq_num );  //
                hdr.tcp.seqNo = hdr.tcp.ackNo;
                hdr.tcp.ackNo = hdr.tcp.seqNo+1;  // belső seq

            }
            else
            {
                new_flags = TCP_flags.ACK ^ TCP_flags.FIN ^ TCP_flags.PSH ^ TCP_flags.URG;
                drop();

                // new_flags = TCP_flags.FIN;
                //new_flags =

            }

            // ACK > Increase sequence number
    /*        if (hdr.tcp.flags & TCP_flags.ACK == TCP_flags.ACK) {
                hdr.tcp.seqNo = hdr.tcp.ackNo;
            }
*/
            // Finished parsing incoming flags..
            hdr.tcp.flags = new_flags;  // ez jó
/*
            // Seat a random sequence number if SYN was set
            if (hdr.tcp.flags & TCP_flags.SYN == TCP_flags.SYN) {
                hdr.tcp.seqNo = 0x01; // Much random, such security
                //hdr.tcp.seqNo = 0x01 + ((bit<32>) hdr.tcp.windowSize); // Much random, such security
            }
*/


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
    } ////█▓▒░ truncate(szám) ... levágja a packet végéről mindent .. (pay loadot)... ha lenne varbit azaza tcp opciónk akkkor ez többet vágna mint kéne

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
         update_checksum(          ////█▓▒░   ez csak az ipv 4
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
// p4 16 beépített függvénye
        update_checksum(  ///█▓▒░  ez a tcp check sum
            //update_checksum_with_payload    ugyan az payload nélkül a checksum eltérés
            hdr.tcp.isValid(),  // fel let parsolva vagy sem
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,               //pseudo ip mező reserverd mezője .. 8 darab 0
                hdr.ipv4.protocol,
                meta.packet_length ,  //// teljes csomag mérete VOLT //TCP length: the length of the TCP header and data

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
            hdr.tcp.checkSum,         // melyik mezőbe updatel
            HashAlgorithm.csum16
        );
        // nem lehetséges hdr.tcp.checkSum = hdr.tcp.checkSum + 35;

/*
    update_checksum(  ///█▓▒░  ez a tcp check sum
            //update_checksum_with_payload    ugyan az payload nélkül a checksum eltérés
            hdr.tcp.isValid(),  // fel let parsolva vagy sem
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr, // AAA sorrend a hibás mert ha ha vfelcserélődik a sorrend akkor mindig ugyan az a eltolás lesz az üzenetekbe
                meta.packet_length,  ////█▓▒░ teljes csomag mérete
                hdr.ipv4.protocol,
                8w0,               //pseudo ip mező reserverd mezője .. 8 darab 0

                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
            //    hdr.tcp.dstPort,// erre jól elszáll a check szám
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,

                hdr.tcp.ecn,
                hdr.tcp.flags,
                hdr.tcp.windowSize,
                // 9w0, nem befojásolja a végeredményt .... 35 eltolás mindig
                hdr.tcp.urgentPtr

            },
            hdr.tcp.checkSum,         // melyik mezőbe updateli
            HashAlgorithm.csum16
        );*/
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
MyParser(),            //
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

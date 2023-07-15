Switch P4:
Type and structures
* Type:
  * tcpPort (48 bit)
  * IP4 Address (32 bit)
  * Mac Address(16 bit)
* Headers:
  * Ethernet (14 byte)
  * Ipv4 (20 byte)
  * Tcp (20 byte)
  * Tcp options (for future purpose ) (max 40 byte)
    * TCP end option  (8 bit)
    * TCP noop option  (8 bit)
    * TCP mss option  (32 bit)
    * TCP ws option  (24 bit)
    * TCP SACKOK  option (16+256 bit)
    * TCP SACK option  (16 bit)
    * TCP timestamp option (80 bit)
Parser:
* First the code extract Ethernet header.
If ethernet type is ipv4, the ipv4 extracted next. The IPv4 header is examined if the protocol is TCP, the TCP header is extracted. Program detect if packet contain any TCP option. Before extract the option from packet it examine the type of it. Then it extract the specific type until reach end option. (the maximum option number is 10)

Checksum inspection:
* If the checksum is not correct the answer is terminated.
Processing:
* First it set the output port, destination ip, and reset flag state.
* Based on TCP flag it whose the response packet type.
* TCP response handle:
  * 3 way handshake to 
  * Data message acknowledge
  * Close the connection
* It is cut the unnecessary tail part 
* At last the  checksum is counted 
Python packet generator:
* Establish TCP connection 
* Send test packet with different payload.
* Terminate the TCP connection. 
Manual to use:
* Environmental to inspect the packet: It is recommended to turned on the feature witch check TCP and IPv4 checksum and validation in Wireshark setting.
* To set Mininet navigate to solution folder: 
  * Make run 
  * Xterm h1 
    * Python3 send _file_w_heartbeat.py

--------OneNote plan--------------------------------------------------------------------------------------------------
https://ikelte.sharepoint.com/sites/P4TCPY/_layouts/OneNote.aspx?id=%2Fsites%2FP4TCPY%2FMegosztott%20dokumentumok%2FGeneral%2Ffeladatok&wd=target%28N%C3%A9vtelen%20szakasz.one%7C1AED9152-429F-4599-A206-2783EDCF723D%2F%29



/*data("1",accept,adapter(["A","B","C"]),ether(vid(["1","2"]),proto([X])),*/
	/*ip(src_addr(["192.168.1.1"]),dst_addr([Y]),*/
	/*tcp_udp_src_port(["80"]),tcp_udp_src_portp_dest_port([Z]),icmp_code([P]))).*/

data("1",accept,adapter(["A","B","C"]),ether(vid(["1","2"]),proto([X])),
	ip(src_addr(["192.168.1.1"]),dst_addr([Y]),
	tcp_udp_src_port(["80"]),tcp_udp_src_portp_dest_port([Z]),icmp_code([P]))).
/* Rejects unmatched packets by default */

data("default",reject,A,ether(vid(B),proto(C)),
	ip(src_addr(D),dst_addr(E),
	tcp_udp_src_port(F),tcp_udp_dest_port(G),icmp_code(H))).
	
/* accept adapter A-C ether vid 1,2 ip src addr 192.168.1.1 tcp src port 80 */

/* Sample Packet : adapter A,ether vid 1 proto 20,ip src addr 192.168.1.1 dest addr 192.168.1.2 tcp src port 80 dst port 50 icmp type 1 */

  
					



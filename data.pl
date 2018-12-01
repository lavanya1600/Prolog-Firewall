	

	accept("1",
	adapter("A,B"),
	ether(vid("1-4"),
	proto("12")),
	ip(src_addr("192.168.1.9"),
	dst_addr("192.168.1.1-192.168.1.6"),
	tcp_udp_src_port("80-100"),
	tcp_udp_dest_port("25"),
	icmp_code("1-3"))).

 	accept("2",
	adapter("A,B,C"),
	ether(vid("1,2"),
	proto("12")),
	ip(src_addr("192.168.1.7"),
	dst_addr("172.24.16.31-172.24.16.40"),
	tcp_udp_src_port("10-20"),
	tcp_udp_dest_port("25"),
	icmp_code("1-3"))).




 	drop("3",
	adapter("A-C"),
	ether(vid("1,2"),
	proto("12")),
	ip(src_addr("192.168.1.3"),
	dst_addr(Z),
	tcp_udp_src_port("80"),
	tcp_udp_dest_port("25"),
	icmp_code("1-3"))).



 	reject("4",
	adapter("G"),
	ether(vid("1,2"),
	proto("12")),
	ip(src_addr("192.168.1.3"),
	dst_addr("any"),
	tcp_udp_src_port("80"),
	tcp_udp_dest_port("25"),
	icmp_code("4"))).

	


	
	


/* Rejects unmatched packets by default */

	





/* accept adapter A-C ether vid 1,2 ip src addr 192.168.1.1 tcp src port 80 */

/* Sample Packet : adapter A,ether vid 1 proto 20,ip src addr 192.168.1.1 dest addr 192.168.1.2 tcp src port 80 dst port 50 icmp type 1 */

  
					



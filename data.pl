data("1",accept,adapter(["A","B","C"]),ether(vid(["1","2"]),proto([X])),
	ip(src_addr(["192.168.1.1"]),dst_addr(Y),
	tcp_udp_src_port(["80"]),tcp_udp_dest_port([Z]),icmp_code([P]))).

	/* accept adapter A-C ether vid 1,2 ip src addr 192.168.1.1 tcp src port 80 */




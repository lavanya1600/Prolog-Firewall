data(accept,adapter(["A","B","C"]),ether(vid(["1","2"]),proto([X])),
	ip(src_addr(["192.168.1.1"]),dst_addr([Y]),
	icmp_code([P]),
	tcp_udp_src_port(["80"]),tcp_udp_src_dest([Z])).

	/* accept adapter A-C ether vid 1,2 ip src addr 192.168.1.1 tcp src port 80 */

data(reject,adapter(["D","B","F"]),ip_addr(["135","123"])).
data(reject,adapter([X]),ip_addr([Y])).


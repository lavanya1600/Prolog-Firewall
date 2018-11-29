contains(X,[X|T]).
contains(X,[H|T]):- contains(X,T).


rule(P1,P2,P3,P4,P5,P6,P7,P8):- data(I,Z,adapter(L1),ether(vid(L2),proto(L3)),ip(src_addr(L4),
								dst_addr(L5),tcp_udp_src_port(L6),tcp_udp_dest_port(L7),icmp_code(L8)))
								,contains(P1,L1),contains(P2,L2),contains(P3,L3),contains(P4,L4),contains(P5,L5),
								contains(P6,L6),contains(P7,L7),contains(P8,L8),test(Z,I).

test(Z,I):- Z=reject,write("Packet Rejected").


test(Z,I):- Z=accept,string_concat("Packet accepted by rule number: ",I,S),write(S).


packet(X):- split_string(X," ,"," ",L),nth0(1,L,P1,_),nth0(4,L,P2,_),nth0(6,L,P3,_),
			nth0(10,L,P4,_),nth0(13,L,P5,_),nth0(17,L,P6,_),nth0(20,L,P7,_),nth0(23,L,P8,_),rule(P1,P2,P3,P4,P5,P6,P7,P8).
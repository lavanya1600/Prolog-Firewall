
rule(X,Y):- data(Z,adapter(L),ip_addr(L2)),contains(X,L),contains(Y,L2), test(Z).
test(Z):- Z=reject,write("Packet Rejected").
test(Z):- Z=accept,write("Packet Accepted").

packet(X):- split_string(X," ,"," ",L),nth0(1,L,P1,_),nth0(3,L,P2,_),nth0(5,L,P3,_),
			nth0(7,L,P4,_),nth0(9,L,P5,_),nth0(11,L,P6,_),nth0(13,L,P7,_),rule(P1,P2,P3,P4,P5,P6,P7).
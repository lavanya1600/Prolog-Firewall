
/* MEMBERSHIP RELATION */


contains(X,[X|T]).
contains(X,[H|T]):- contains(X,T).



/* FUNCTION TO CALULATE THE LENGTH OF THE LIST */


len([],0).
len([H|T],L):- len(T,M), L is M+1.


/**********************************************************************************************************/

/*  split_string() splits a string and puts the elements in a List (LIBRARY FUNCTION) */

/* nth0() selects an element from the list (LIBRARY FUNCTION) */

rule(P1,P2,P3,P4,P5,P6,P7,P8):- accept(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),
								validate_adapter(P1,L1),
								validate(P2,L2),
								validate(P3,L3),
								validate_ip(P4,L4),
								validate_ip(P5,L5),
								validate(P6,L6),
								validate(P7,L7),
								validate(P8,L8),
								Z=accept,test(Z,I);

								
								reject(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),
								validate_adapter(P1,L1),
								validate(P2,L2),
								validate(P3,L3),
								validate_ip(P4,L4),
								validate_ip(P5,L5),
								validate(P6,L6),
								validate(P7,L7),
								validate(P8,L8),
								Z=reject,
								test(Z,I);
								
								
								drop(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),
								validate_adapter(P1,L1),
								validate(P2,L2),
								validate(P3,L3),
								validate_ip(P4,L4),
								validate_ip(P5,L5),
								validate(P6,L6),
								validate(P7,L7),
								validate(P8,L8),
								Z=drop,
								test(Z,I).
								




packet(X):- split_string(X," ,"," ",L),  /* Splits the input string and stores the values in list L */
			nth0(1,L,P1,_),
			nth0(4,L,P2,_),
			nth0(6,L,P3,_),
			nth0(10,L,P4,_),
			nth0(13,L,P5,_),
			nth0(17,L,P6,_),
			nth0(20,L,P7,_),
			nth0(23,L,P8,_),
			rule(P1,P2,P3,P4,P5,P6,P7,P8), /* P1-P8 contain the values of the firewall parameters */
			len(L,Q).



/* rule function is defined that takes the values of the firewall parametres and matches them from accept,*/
	/*reject or drop rules from our firewall database */




								

/* check_lists Function checks whether a member of List1 is member of an element in List2 */

check_lists([],[]).
check_lists([H1|T1],[H2|T2]):- contains(H1,H2),check_lists(T1,T2).


/*  Prints Rejected Message When A Packet Is Rejected  */

test(Z,I):- Z=reject,string_concat("Packet rejected by rule : ",I,S),write(S).


/* Prints Accepted Message When A Package Is Accepted */

test(Z,I):- Z=accept,string_concat("Packet accepted by rule : ",I,S),write(S).

test(Z,I):- Z=drop.


validate_adapter(P1,L1):- 	L1="any";
							split_string(L1,",","",L), 
							len(L,X), X>1,contains(P1,L);
							split_string(L1,"-","",L), 
							len(L,X), X=2,
							nth0(0,L,X1,_), 
							nth0(1,L,X2,_),
							string_code(_,X1,Y1),
							string_code(_,X2,Y2),
							string_code(_,P1,Y3),
							(Y3>Y1;Y3=Y1),
							(Y3<Y2;Y3=Y2);
							P1=L1.

validate(P1,L1):- 	L1="any";
					split_string(L1,",","",L), 
					len(L,X), X>1,contains(P1,L);
					split_string(L1,"-","",L), 
					len(L,X), X=2,
					nth0(0,L,X1,_), 
					nth0(1,L,X2,_),
					number_codes(Y1,X1),
					number_codes(Y2,X2),
					number_codes(Y3,P1),
					(Y3>Y1;Y3=Y1),
					(Y3<Y2;Y3=Y2);
					P1=L1.


validate_ip(P,L):- L="any";
				   split_string(L,",","",X),
				   len(X,Y), Y>1,contains(P,X);
				   split_string(L,"-","",X),
				   nth0(0,X,V1,_),
				   nth0(1,X,V2,_),
				   split_string(V1,".","",L1),
				   split_string(V2,".","",L2),
				   nth0(3,L1,C1,_),
				   nth0(3,L2,C2,_), 
				   split_string(P,".","",L3),
				   nth0(3,L3,C3,_),
				   number_codes(Y1,C1),
				   number_codes(Y2,C2),
				   number_codes(Y3,C3),
				   (Y3>Y1;Y3=Y1),
				   (Y3<Y2;Y3=Y2);
				   P=L.





/* MEMBERSHIP RELATION */


contains(X,[X|T]).
contains(X,[H|T]):- contains(X,T).



/* FUNCTION TO CALULATE THE LENGTH OF THE LIST */


len([],0).
len([H|T],L):- len(T,M), L is M+1.


/**********************************************************************************************************/

/*  split_string() splits a string and puts the elements in a List (LIBRARY FUNCTION) */

/* nth0() selects an element from the list (LIBRARY FUNCTION) */


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



/* rule function is defined that takes the values of the firewall parametres and matches them from accept,
	reject or drop rules from our firewall database */


rule(P1,P2,P3,P4,P5,P6,P7,P8):- (accept(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),term_string(F,P1),string_chars(L1,L9),contains(',',L9),Z=accept;

								reject(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),Z=reject;

								drop(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),Z=drop)
								
							    ,check_lists([F,P2,P3,P4,P5,P6,P7,P8],[L9,L2,L3,L4,L5,L6,L7,L8]),
								test(Z,I).
rule(P1,P2,P3,P4,P5,P6,P7,P8):- accept(I,adapter(L1),
								ether(vid(L2),proto(L3)),
								ip(src_addr(L4),
								dst_addr(L5),
								tcp_udp_src_port(L6),
								tcp_udp_dest_port(L7),
								icmp_code(L8))),term_string(F,P1),string_chars(L1,L9),contains('-',L9),Z=accept,
								nth0(0,L9,Q1,_), F>=Q1, nth0(2,L9,Q2,_), F<=Q2,check_lists([P2,P3,P4,P5,P6,P7,P8],[L2,L3,L4,L5,L6,L7,L8]),test(Z,I).




/* check_lists Function checks whether a member of List1 is member of an element in List2 */


check_lists([],[]).
check_lists([H1|T1],[H2|T2]):- contains(H1,H2),check_lists(T1,T2).


/*  Prints Rejected Message When A Packet Is Rejected  */

test(Z,I):- Z=reject,string_concat("Packet rejected by rule : ",I,S),write(S).


/* Prints Accepted Message When A Package Is Accepted */

test(Z,I):- Z=accept,string_concat("Packet accepted by rule : ",I,S),write(S).




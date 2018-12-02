
CODE FILE - assign.pl
DATABASE FILE - data.pl


Predicates used : 
		
			1. contains() - Checks if an element is contained in the list.

			2. len() - Calulates the length of the list.

			3. packet() - Receives the input from the user and extracts the values of the parameters.

			4. rule() - Recevies the parameter values from the packet() predicate and checks for accept,reject and 
						drop rules from the database.

			5. message() - Prints accept or reject message.

			6. accept(), reject(), drop() - Checks for accept, reject and drop rules from our databse; Used in rule 								predicate.

			7. validate_adapter() - Validates the value of adapter parameter from any of the rules defined in the 							database.

			8. validate_ip() -  Validates the value of IP parameter from any of the rules defined in the 							database.

			9. validate() - Validates the values of all other parameters.


Format of database file - 
		
			To add accept, reject or drop rule, use accept(), reject() or drop() predicate as follows :

		1.	First argument - A String, defines the rule number.

		2.	Second Argument - adapter() predicate which contains the adapter values.

							  Values can be given in the following formats - 

							  			1.	"A"         (SINGLE VALUE)
							  			2.	"A,B,C"		(COMMA SEPERATED VALUES)
							  			3. 	"A-C"		(RANGE OF VALUES)

							  Value of the adapter predicate should be a string in the format given above.

				EXAMPLE - adapter("A-C")

		3. Third Argument - ether(vid(),proto()) predicate which contains predicates vid() and proto()

							Value of vid() is a string in the following format : 

									1. "1"				(SINGLE VALUE)
									2  "1,2,3"			(COMMA SEPERATED VALUES)
									3. "1-3"			(RANGE OF VALUES)

							Value of proto() is a string in the following format:

									1.	"12"			(SINGLE VALUE)
									2. 	"10,11,12"		(COMMA SEPERATED VALUES)
									3.	"10-12"			(RANGE OF VALUES)

				EXAMPLE : ether(vid("1,2"),proto("12"))

		4. Fourth Argument - ip(src_addr(),
							 dst_addr(),
							 tcp_udp_src_port(),
							 tcp_udp_dest_port(),
							 icmp_code())	

							 Value of src_addr() is a string in the following format: 

							 		1.	"192.168.1.1"					(SINGLE VALUE)
							 		2.	"172.24.16.31,192.168.1.3"		(COMMA SEPERATED VALUES)
							 		3.	"192.168.1.1-192.168.1.5"		(RANGE OF VALUES)

							 Value of dst_addr() is a string in the following format: 

							 		1.	"192.168.1.5"
							 		2.	"172.24.16.32,192.168.1.3"
							 		3.	"192.168.1.5-192.168.1.9"

							 Value of tcp_udp_src_port() and tcp_udp_dest_port() is a string in the following format:

							 		1.	"80"
							 		2.	"20,80"
							 		3.	"80-100"	

							 Value of icmp_code() is a string in the following format:

							 		1.	"2" 
							 		2.	"2,3,4"
							 		3.	"2-4"

					EXAMPLE - 	ip(src_addr("192.168.1.7"),
								dst_addr("172.24.16.31-172.24.16.40"),
								tcp_udp_src_port("10-20"),
								tcp_udp_dest_port("25"),
								icmp_code("1-3"))


IMPORTANT - TO SPECIFY THE VALUE OF A PARAMETER AS 'ANY' IN A RULE, JUST PASS THE STRING "any" AS A VALUE TO THAT 			  PARAMETER.


	A sample reject rule : 	reject("1",
							adapter("G"),
							ether(vid("1,4"),
							proto("12")),
							ip(src_addr("192.168.1.3"),
							dst_addr("any"),
							tcp_udp_src_port("20,80"),
							tcp_udp_dest_port("25"),
							icmp_code("4"))).

	This rule translates to ---> "reject adapter G ether vid 1-4 proto 12 ip src addr 192.168.1.3 dest addr any 							  tcp src port 20,80 dest port 25 icmp type 4" 


	IMPORTANT - WE HAVE ASSUMED THAT THE VALUES COMING IN THE PACKET ARE CORRECT i.e. IN THE CORRECT FORMAT AS 					SPECIFIED.


	SAMPLE INPUTS HAVE BEEN PROVIDED IN THE sample.pl FILE, PLEASE REFER TO THAT FOR THE INPUT FORMAT.
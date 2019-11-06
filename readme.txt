CSCE 3530.001 - Lab 3
Created by Zachery Friedman - zmf0010 - zacheryfriedman@my.unt.edu

Description: 
    The server program receives a SYN packet from the client and sends a SYN-ACK packet in response.
    It then receives an ACK packet from the client, and the TCP connection is established.
    When the closing sequence is initialized by a FIN packet received from the client,
    the server sends first an ACK packet to acknowledge the client's request, and then a FIN packet
    to mark the end of transmission. Once the server received an ACK packet in response, the connection is terminated.

    The client program initializes the TCP 3-way handshake by creating a SYN packet and sending it to the server.
    When a SYN-ACK packet is received from the server, an ACK is sent from the client in response.
    The client then initiates the closing sequence by constructing a FIN packet as a request to end transmission.
    Once the client receives both an ACK and a FIN packet from the server, an ACK packet is sent in response
    and the connection is terminated.

Usage:
    - Compile the client code:              gcc -o client client.c
    - Compile the server code:              gcc -o pserver server.c
    - First, execute the server program:    ./pserver <port number>
    - Then, execute the client program:     ./client <port number>
    - The program will then continue with the TCP 3-way handshake and closing sequence before closing.
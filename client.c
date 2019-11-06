/*
  Created by Zach Friedman - zmf0010 - zacheryfriedman@my.unt.edu

  Description: When compiled and run with the included server.c file, this client is used
  to simulate a TCP 3-way handshake between the two programs. This is done by simply passing
  the values of the struct (declared in the header) across the socket and changing the bits
  as needed.

  Flag hex values obtained from http://rapid.web.unc.edu/resources/tcp-flag-key/
*/

#include "header.h"

int main(int argc, char **argv) {

    //tcp struct
    tcp_hdr tcp_seg;

    //socket variables
    int sockfd, portno, n;
    int len = sizeof(struct sockaddr);
    struct sockaddr_in servaddr;

    //usage: ./client <port number>
    //url: <some URL>
    if(argc != 2) {
        printf("usage: ./client <port number>\n");
        exit(1);
    }

    /* AF_INET - IPv4 IP , Type of socket, protocol*/
    portno = atoi(argv[1]);
    sockfd=socket(AF_INET, SOCK_STREAM, 0);

    //error checking
    if(sockfd < 0) {
        perror("socket() error");
        exit(1);
    }

    //clear the buffer, necessary details for connecting to proxy
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(portno); // Server port number
 
    /* Convert IPv4 and IPv6 addresses from text to binary form */
    inet_pton(AF_INET, "127.0.0.1", &(servaddr.sin_addr)); //change the IP here to use on CSE01/CSE02
 
    /* Connect to the server, error check */
    if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0) {
        perror("connect() error");
        exit(1);
    }

    //prints after successful connection
    printf("Connected to server...\n");

    //construct SYNchronization pkt
    syn(&tcp_seg);

    //confirm sending of SYN, show results
    printf("\nSYN packet initialized...\n");
    PrintStruct(&tcp_seg);

    //track starting checksum and sequence numver
    int initialChecksum = tcp_seg.cksum;
    int initSeq = tcp_seg.seq; //track initial client sequence number
    int serverSeq = tcp_seg.seq; //track initial server sequence number

    //write SYN to socket
    printf("\nSending SYN packet...\n");
    n = write(sockfd, &tcp_seg, sizeof(tcp_seg));

    //read SYN-ACK from socket
    while(1) {
        n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
        break;
    }

    //check for hex value for flag SYN-ACK, checksum match; print result and send ACK
    if(tcp_seg.hdr_flags == 0x12 && tcp_seg.cksum == initialChecksum) {

        //print SYN-ACK packet from server
        printf("\nSYN-ACK packet received...\n");
        PrintStruct(&tcp_seg);

        //send ACK packet to server
        printf("\nSending ACK packet...\n");
        ack(&tcp_seg, serverSeq, initSeq);
        n = write(sockfd, &tcp_seg, sizeof(tcp_seg));
    }

    printf("\nTCP HANDSHAKE COMPLETE\n");

    //BEGIN CLOSING SEQUENCE
    printf("\nBEGIN CLOSING SEQUENCE\n");
    cli_fin(&tcp_seg); //construct FIN packet

    int finClientSeq = tcp_seg.seq; //track initial client sequence number used in FIN packet
    int newChecksum = ComputeChecksum(tcp_seg);

    n = write(sockfd, &tcp_seg, sizeof(tcp_seg)); //write FIN packet to socket

    //read ACK from server regarding FIN bit that was sent above
    while(1) {
        n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
        break;
    }

    //if checksums match and ACK bit = 1, print results
    if(tcp_seg.cksum == newChecksum && tcp_seg.hdr_flags == 0x10) {
        printf("\nACK packet received...\n");
        PrintStruct(&tcp_seg);
    }

    int finServerSeq = tcp_seg.seq;

    //receive FIN packet from server
    while(1) {
        n = read(sockfd, &tcp_seg, sizeof(tcp_seg));
        break;
    }

    //if checksums match and FIN bit = 1, print result and send ACK
    if(tcp_seg.cksum == newChecksum && tcp_seg.hdr_flags == 0x01) {

        //print FIN packet from server
        printf("\nFIN packet received...\n");
        PrintStruct(&tcp_seg);

        //send ACK as response
        printf("\nSending ACK packet...\n");
        cli_fin_ack(&tcp_seg, finServerSeq, finClientSeq);
        n = write(sockfd, &tcp_seg, sizeof(tcp_seg));
    }

    //close the connection to the server
    close(sockfd);
    
    return 0;
}

/*
    Description: This function is used to calculate a checksum based on the provided TCP header info.
*/
int ComputeChecksum(tcp_hdr tcp_segment) {

    unsigned short int cksum_arr[12];
    unsigned int i, sum = 0, cksum;

    memcpy(cksum_arr, &tcp_segment, 24);

    for(i = 0; i < 12; i++) {
        sum = sum + cksum_arr[i]; //compute sum
    }

    cksum = sum >> 16; //fold once
    sum = sum & 0x0000FFFF;
    sum = cksum + sum;

    cksum = sum >> 16; //fold again
    sum = sum & 0x0000FFFF;
    sum = cksum + sum;

    /* XOR the sum for the checksum */
    return (0xFFFF ^ cksum);
}

/*
    Description: This function constructs the SYNchronization packet that is sent to the server
    and used to initialize a TCP connection. Assigns values to a tcp_hdr struct.
    SYN = 1, Seq = rand(x).
*/
void syn(tcp_hdr* tcp_segment) {

    //generate a newchecksum
    int newChecksum = ComputeChecksum(*tcp_segment);

    tcp_segment->src = 4040; 
    tcp_segment->dest = 4040;
    tcp_segment->seq = rand(); //random sequence number chosen
    tcp_segment->ack = 0;
    tcp_segment->hdr_flags = 0x02; 
    tcp_segment->rec = 0;
    tcp_segment->cksum = newChecksum;
    tcp_segment->ptr = 0;
    tcp_segment->opt = 0;
}

/*
    Description: Print the contents of a tcp_hdr struct.
*/
void PrintStruct(tcp_hdr* tcp_struct) {

    printf("        Source:        0x%04X\n", tcp_struct->src);
    printf("   Destination:        0x%04X\n", tcp_struct->dest);
    printf("           Seq:        0x%04X\n", tcp_struct->seq);
    printf("           ACK:        0x%04X\n", tcp_struct->ack);
    printf(" Header Length:        0x%04X\n", tcp_struct->headLength);
    printf("         Flags:        0x%04X\n", tcp_struct->hdr_flags);
    printf("           Rec:        0x%04X\n", tcp_struct->rec);
    printf("         Cksum:        0x%04X\n", tcp_struct->cksum);
    printf("           Ptr:        0x%04X\n", tcp_struct->ptr);
    printf("           Opt:        0x%04X\n", tcp_struct->opt);
}

/*
    Description: this function is used to construct an ACK packet used in the TCP handshake.
    Assigns appropriate values to tcp_hdr struct.
*/
void ack(tcp_hdr* tcp_segment, int serverSeq, int clientSeq) {

    tcp_segment->seq = clientSeq + 1; //sequence number = initial client sequence number + 1
    tcp_segment->ack = serverSeq + 1; //acknowledgement number = initial server sequence number + 1
    tcp_segment->hdr_flags = 0x10; //hex value for flag ACK
    tcp_segment->cksum = ComputeChecksum(*tcp_segment); //generate new checksum, should be the same
}

/*
    Description: This function is used to construct a FIN packet, used by the client to initiate
    the closing sequence.
*/
void cli_fin(tcp_hdr* tcp_segment) {

    tcp_segment->seq = rand(); //sequence number = ISN(c)
    tcp_segment->ack = 0;
    tcp_segment->hdr_flags = 0x01; //0x01 hex -> FIN bit = 1
    tcp_segment->cksum = ComputeChecksum(*tcp_segment); //generate new checksum, should be the same
}

/*
    Description: This function is used by the client to construct the final ACK packet
    in the closing sequence.
*/
void cli_fin_ack(tcp_hdr* tcp_segment, int serverSeq, int clientSeq) {

    tcp_segment->seq = clientSeq + 1; //sequence number = ISN(c) + 1
    tcp_segment->ack = serverSeq + 1; //acknowledgement number = ISN(s) + 1
    tcp_segment->hdr_flags = 0x10; //0x10 hex -> ACK bit = 1
    tcp_segment->cksum = ComputeChecksum(*tcp_segment); //generate new checksum, should be the same
}
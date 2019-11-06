/*
    Created by Zachery Friedman - zmf0010 - zacheryfriedman@my.unt.edu

    This program is designed to simulate a TCP 3-Way Handshake.

    Flag hex values obtained from http://rapid.web.unc.edu/resources/tcp-flag-key/
*/

#include "header.h"

int main(int argc, char **argv) {

    //declaring tcp_hdr struct
    tcp_hdr tcp_seg;

    //socket variables
    int listen_fd, conn_fd, portno, clilen, n;
    struct sockaddr_in servaddr, cliaddr;

    //usage: ./pserver <port number>
    if(argc != 2) {
        printf("usage: ./pserver <port number>\n");
        exit(1);
    }

    //IPv4, TCP, protocol
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    //error checking
    if(listen_fd < 0) {
        perror("socket(1) error");
        exit(1);
    }

    //filling out socket structure
    bzero(&servaddr, sizeof(servaddr));
    portno = atoi(argv[1]);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(portno);

    //bind above details to socket, check for errors
    if(bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind(1) error");
        exit(1);
    }

    //listen for connection from client
    if(listen(listen_fd, 1) < 0) {
        perror("listen(1) error");
        exit(1);
    }

    printf("Server created successfully, listening...\n");

    while(1) {
        clilen = sizeof(cliaddr);

        conn_fd = accept(listen_fd, (struct sockaddr *)NULL, NULL);

        //error checking
        if(conn_fd < 0) {
            perror("accept(1) error");
            exit(1);
         }

        printf("Client connected...\n");

        //initial read, SYN should equal 1
        n = read(conn_fd, &tcp_seg, sizeof(tcp_seg)); //read struct from socket

        if(tcp_seg.hdr_flags == 0x02) {
            printf("\nSYN packet received...\n");
            PrintStruct(&tcp_seg);
        }

        int checksum1 = ComputeChecksum(tcp_seg); //track initial checksum
        int synCheck = tcp_seg.hdr_flags; //track SYN bit
        int clientSeq = tcp_seg.seq; //track client sequence number

        //generate SYN-ACK
        syn_ack(&tcp_seg, clientSeq);

        //check that checksums match, SYN = 1
        if(checksum1 == tcp_seg.cksum && synCheck == 0x02) {
            printf("\nSending SYN-ACK...\n");
            n = write(conn_fd, &tcp_seg, sizeof(tcp_seg));
        }

        //read ACK sent by client
        n = read(conn_fd, &tcp_seg, sizeof(tcp_seg));

        //check conditions for ACK
        if(tcp_seg.cksum == checksum1 && tcp_seg.hdr_flags == 0x10) {
            printf("\nACK packet received...\n");
            PrintStruct(&tcp_seg);
        }

        printf("\nTCP HANDSHAKE COMPLETE\n"); 

        //BEGIN CLOSING SEQUENCE
        printf("\nBEGIN CLOSING SEQUENCE\n");
        n = read(conn_fd, &tcp_seg, sizeof(tcp_seg));

        int checksum2 = ComputeChecksum(tcp_seg); //track checksum
        int finClientSeq = tcp_seg.seq; //track client sequence number sent in FIN packet
        int serverSeq = rand(); //used for server-side ACK; this is hacky

        //check for matching checksums and FIN bit = 1
        if(tcp_seg.cksum == checksum2 && tcp_seg.hdr_flags == 0x01) {

            //print out FIN packet from client
            printf("\nFIN packet received...\n");
            PrintStruct(&tcp_seg);

            //send ACK packet as response
            printf("\nSending ACK packet...\n");
            ack(&tcp_seg, serverSeq, finClientSeq);
            n = write(conn_fd, &tcp_seg, sizeof(tcp_seg));

            //send FIN packet as response
            printf("\nSending FIN packet...\n");
            svr_fin(&tcp_seg, serverSeq, finClientSeq);
            n = write(conn_fd, &tcp_seg, sizeof(tcp_seg));
        }

        n = read(conn_fd, &tcp_seg, sizeof(tcp_seg));

        //if checksums match and ACK bit = 1, print result and close connection
        if(tcp_seg.cksum == checksum2 && tcp_seg.hdr_flags == 0x10) {
            printf("\nACK packet received...\n");
            PrintStruct(&tcp_seg);
        }

        close(conn_fd);
        break;
    }

    close(listen_fd);
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
    Description: This function constructs a SYN-ACK packet used in the TCP handshake.
*/
void syn_ack(tcp_hdr* tcp_segment, int clientSeq) {

    int newChecksum = ComputeChecksum(*tcp_segment);

    tcp_segment->seq = rand(); //server sequence number = ISN(s)
    tcp_segment->ack = clientSeq + 1; //ACK = ISN(c) + 1
    tcp_segment->hdr_flags = 0x12; //hex value for flag SYN-ACK
    tcp_segment->cksum = newChecksum; //generate new checksum, should be the same
}

/*
    Description: This function is used by the server to acknowledge the client's FIN packet in the
    closing sequence.
*/
void ack(tcp_hdr* tcp_segment, int serverSeq, int clientSeq) {

    tcp_segment->seq = serverSeq;
    tcp_segment->ack = clientSeq + 1;
    tcp_segment->cksum = ComputeChecksum(*tcp_segment);
    tcp_segment->hdr_flags = 0x10; //0x10 hex -> ACK flag = 1
}

/*
    Description: This function is used to construct the FIN packet that is sent just after the ACK packet
    from the server.
*/
void svr_fin(tcp_hdr* tcp_segment, int serverSeq, int clientSeq) {

    tcp_segment->seq = serverSeq;
    tcp_segment->ack = clientSeq + 1;
    tcp_segment->hdr_flags = 0x01;
    tcp_segment->cksum = ComputeChecksum(*tcp_segment);
}
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdlib.h>
#include <fcntl.h>

#define BUFFER_SM 1000
#define BUFFER_MD 10000
#define BUFFER_LG 100000
#define PORT_BUF 16
#define SEQ_ACK_OPT_BUF 32
#define HEAD_LENGTH_BUF 4
#define RES_FLAG_BUF 6



//replicating a TCP packet using a structure
typedef struct {
    unsigned short int src; //source port #
    unsigned short int dest; //destination port #
    unsigned int seq; //sequence #
    unsigned int ack; //acknowledgement #
    unsigned int headLength; //header length
    unsigned int reserved; //reserved
    unsigned short int hdr_flags; //flags
    unsigned short int rec; //receive window, set to 0
    unsigned short int cksum; //checksum to be computed after header and data is populated
    unsigned short int ptr; //urgent data ptr, set to 0
    unsigned int opt; //options, set to 0
} tcp_hdr;

int ComputeChecksum(tcp_hdr tcp_segment); //function to calculate checksum 
void syn(tcp_hdr* tcp_segment); //function to create SYN packet (client side)
void syn_ack(tcp_hdr* tcp_segment, int clientSeq); //function to create SYN-ACK pkt (server side)
void ack(tcp_hdr* tcp_segment, int serverSeq, int clientSeq); //function to create ACK pkt (client side)
void svr_fin(tcp_hdr* tcp_segment, int serverSeq, int clientSeq); //used by server to construct FIN packet in closing sequence
void cli_fin(tcp_hdr* tcp_segment); //used by client to construct initial FIN packet to start closnig sequence
void cli_fin_ack(tcp_hdr* tcp_segment, int serverSeq, int clientSeq); //used by the client to constuct the final ACK packet in closing sequence
void PrintStruct(tcp_hdr* tcp_struct); //print contents of struct
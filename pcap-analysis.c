#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>  // For inet_ntop function (converts IP to string) and address size definitions

#define TCP_TYPE_NUM 6
#define LEFT 0
#define RIGHT 1
#define YES 1
#define NO 0

#define MAX_TCP_SESSION_CONNECTION_STORAGE 100

/*Packet Information Array Location assuming VLAN (802.1q) Tag is not included in the Ethernet frame*/
/* If VLAN tag is in the Ethernet frame, then the following protocol field location must be shifted by the length of the VLAN Tag field */
#define IP_HDR_LEN_LOC 14 /*IP Packet header Length */
#define TCP_TYPE_LOC 23 /*TCP packet type */
#define TCP_SRC_PORT 34 /*2 bytes */
#define TCP_DST_PORT 36 /*2 bytes */
#define SEQ_NUM 38 /*4 Bytes */
#define ACK_NUM 42 /*4 Bytes */
#define IP_ADDR_START_LOC_VLAN_TYPE 30
#define IP_ADDR_START_LOC_IP_TYPE 26
#define IP_PKT_SIZE_LOC_VLAN_TYPE 20 /*2 bytes from this location*/
#define IP_PKT_SIZE_LOC_IP_TYPE 16 /*2 bytes from this location*/

// EtherType value
// 0x0800 : IPv4 datagram
// 0x0806 : ARP frame
// 0x8100 : IEEE 802.1Q frame
// 0x86DD : IPv6 frame
#define ETHER_PROTOCOL_TYPE_LOC 12
#define IP_PAYLOAD_TYPE_LOC 23 /*ICMP type, size:1 Byte, value: 0X01 */
#define ICMP_TYPE_LOC 34 /*1 byte */

/*packet information */
#define IP_PAYLOAD_ICMP 1
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define VLAN_TYPE 129 /*HEX=81 00*/
#define IP_TYPE 8 /*packet type */
#define NUM_PKT 1000 /*number of packets in a tcpdump file */
#define MAX_PKT_LEN 1700
#define TCP_FLAG_SYN 0x02 // SYN Flag
#define TCP_FLAG_FIN 0x01 // FIN Flag

#if defined(_WIN32)
typedef unsigned int u_int;
#endif

unsigned int pkt_header[4];
unsigned char one_pkt[MAX_PKT_LEN];

// Global Header < -- The pcap file contains this structure at the beginning.
struct pcap_file_header {
    unsigned int magic;            // 4 bytes  magic number 
    unsigned short version_major;  // 2 bytes  major version number 
    unsigned short version_minor;  // 2 bytes  minor version number
    unsigned int thiszone;         // 4 bytes  GMT to local correction
    unsigned int sigfigs;          // 4 bytes  accuracy of timestamps
    unsigned int snaplen;          // 4 bytes  max length of captured packets, in octets
    unsigned int linktype;         // 4 bytes  data link type
};


// Record (Packet) Header <-- this is not a protocol header
struct pcap_pkthdr {
    unsigned int time_sec;            // 4 bytes  timestamp seconds
    unsigned int time_usec;           // 4 bytes  timestamp microseconds
    unsigned int caplen;              // 4 bytes  number of octets of packet saved in file
    unsigned int off_wire_pkt_length; // 4 bytes  actual length of packet
};

// Ethernet_header
struct ethernet_header {
    uint8_t dest_mac[6];   // Destination MAC address
    uint8_t src_mac[6];    // Source MAC address
    uint16_t ethertype;    // EtherType field (2 bytes)
};


// IPv4 Header
struct ipv4_header {
    uint8_t version_ihl;          // 4 bits for version (should be 4) + 4 bits for IHL (header length)
    uint8_t dscp_ecn;             // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;        // Total length of the IP packet (header + data)
    uint16_t identification;      // Identification for packet fragmentation
    uint16_t flags_fragment_offset; // 3 bits for flags + 13 bits for fragment offset
    uint8_t ttl;                  // Time to Live (TTL)
    uint8_t protocol;             // Protocol (e.g., TCP = 6, UDP = 17)
    uint16_t header_checksum;     // Header checksum
    uint32_t source_ip;           // Source IP address (32-bit)
    uint32_t destination_ip;      // Destination IP address (32-bit)
};

// IPv6 Header
struct ipv6_header {
    uint32_t version_traffic_class_flow_label;  // 4 bits for version (6) + 8 bits for traffic class + 20 bits for flow label
    uint16_t payload_length;      // Length of the payload (data) excluding the header
    uint8_t next_header;          // Identifies the type of the next header (similar to Protocol in IPv4)
    uint8_t hop_limit;            // Replaces TTL (time-to-live)
    uint8_t source_ip[16];        // Source IPv6 address (128 bits)
    uint8_t destination_ip[16];   // Destination IPv6 address (128 bits)
};


// TCP header
struct tcp_header {
    uint16_t source_port;         // Source port
    uint16_t destination_port;    // Destination port
    uint32_t sequence_number;     // Sequence number
    uint32_t ack_number;          // Acknowledgment number
    uint8_t data_offset;          // Data offset (header length)
    uint8_t flags;                // Flags (SYN, ACK, FIN, etc.)
    uint16_t window_size;         // Window size
    uint16_t checksum;            // Checksum
    uint16_t urgent_pointer;      // Urgent pointer
};


unsigned int bits_to_ui(char* x, int byte_count, int order)
/*********************************************/
/* Convert bits to unsigned int  */
/*********************************************/
{
    unsigned int displayMask = 1;
    int i, j, location = 0;
    unsigned int result = 0;

    if (order == 0) {
        for (j = byte_count - 1; j >= 0; j--) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask) {
                    result = result + pow(2, location);
                    //printf("1");
                }
                else {
                    //printf("0");
                }

                location++;
                x[j] >>= 1;
            }
        }

        //printf("\n");
    }
    else {
        for (j = 0; j < byte_count; j++) {
            for (i = 1; i <= 8; i++) {
                if (x[j] & displayMask)
                    result = result + pow(2, location);
                location++;
                x[j] >>= 1;
            }
        }
    }

    return result;
}

void ping_response_time_finder(char* in_filename)
{
    FILE* fd;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    int k = 0;
    double start_time, end_time;
    int looking_for_start;

    fd = fopen(in_filename, "rb");
    if (fd < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd) == 0) {
        perror("File header Error");
        exit(1);
    }

    looking_for_start = YES;

    while (!feof(fd)) {
        for (k = 0; k < MAX_PKT_LEN; k++)
            one_pkt[k] = '\0';

        fread(pkt_header, sizeof(unsigned int), 4, fd);
        captured_len = pkt_header[2];
        if (captured_len == 0) {
            // do nothing
        }
        else {
            if (looking_for_start == YES) {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                start_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REQUEST) {
                    looking_for_start = NO;
                }
            }
            else {
                fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd);
                end_time = (double)pkt_header[0] + (((double)pkt_header[1]) / 1000000);

                if ((unsigned int)one_pkt[IP_PAYLOAD_TYPE_LOC] == IP_PAYLOAD_ICMP && (unsigned int)one_pkt[ICMP_TYPE_LOC] == ICMP_REPLY) {
                    looking_for_start = YES;

                    printf("%d.%d.%d.%d %d %f\n", (unsigned int)one_pkt[26], (unsigned int)one_pkt[27],
                        (unsigned int)one_pkt[28], (unsigned int)one_pkt[29], captured_len, end_time - start_time);
                }
            }
        }
    }

    fclose(fd);

} /*end func */

void fix_frame_len(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        if (captured_len > 0) {
            fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);
            if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x08) // 0x0800 : IPv4 datagram.
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 1] + 14;
            else if ((unsigned int)one_pkt[ETHER_PROTOCOL_TYPE_LOC] == 0x81) // 0x8100 : IEEE 802.1Q frame
                pkt_header[3] = ((unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 4] << 8) + (unsigned int)one_pkt[IP_PKT_SIZE_LOC_IP_TYPE + 5] + 18;

            if (!feof(fd_in)) {
                fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
                fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
            }
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

// Function to convert IP string to uint32_t
uint32_t ipToUint(const char* ip) {
    struct in_addr ip_addr;
    inet_pton(AF_INET, ip, &ip_addr);  // Convert to network byte order
    return ntohl(ip_addr.s_addr);      // Convert to host byte order for comparison
}

void uint32_to_ip(uint32_t ip_addr, char *ip_str) {
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = ip_addr;

    // Convert numeric IP to string and store it in the provided buffer
    if (inet_ntop(AF_INET, &ip_addr_struct, ip_str, INET_ADDRSTRLEN) == NULL) {
        strcpy(ip_str, "Invalid IP");  // Handle error by setting an error message in the buffer
    }
}

// Function to round a double to 'n' significant figures
double round_to_sig_figs(double num, int n) {
    if (num == 0) {
        return 0;
    }
    double d = ceil(log10(fabs(num))); // Find the number of digits before the decimal point
    int power = n - (int)d;  // Determine how many digits to the right of the decimal to keep
    double magnitude = pow(10, power); // Shift decimal to the right
    return round(num * magnitude) / magnitude; // Round and shift back
}

void ip_address_change(char* in_filename, char* output_filename)
{
    FILE *fd_in, *fd_out;
    unsigned int file_header[6], pkt_header[4], captured_len;
    unsigned char one_pkt[MAX_PKT_LEN];
    unsigned int src_ip_1st_digit, src_ip_2nd_digit, src_ip_3rd_digit, src_ip_4th_digit;
    unsigned int dst_ip_1st_digit, dst_ip_2nd_digit, dst_ip_3rd_digit, dst_ip_4th_digit;
    unsigned int src_port_num, dst_port_num;
    unsigned int seq_n = 0, ack_n = 0;

    fd_in = fopen(in_filename, "rb");
    if (fd_in < 0) {
        perror("Unable to open input file");
        exit(1);
    }

    fd_out = fopen(output_filename, "wb");
    if (fd_out < 0) {
        perror("Unable to open output file");
        exit(1);
    }

    if (fread(file_header, sizeof(unsigned int), 6, fd_in) == 0) {
        perror("File header Error");
        exit(1);
    }

    fwrite(file_header, sizeof(unsigned int), 6, fd_out);

    while (!feof(fd_in)) {
        fread(pkt_header, sizeof(unsigned int), 4, fd_in);
        captured_len = pkt_header[2];

        fread(&one_pkt[0], sizeof(unsigned char), captured_len, fd_in);

        src_ip_1st_digit = (unsigned int)one_pkt[26];
        src_ip_2nd_digit = (unsigned int)one_pkt[27];
        src_ip_3rd_digit = (unsigned int)one_pkt[28];
        src_ip_4th_digit = (unsigned int)one_pkt[29];
        dst_ip_1st_digit = (unsigned int)one_pkt[30];
        dst_ip_2nd_digit = (unsigned int)one_pkt[31];
        dst_ip_3rd_digit = (unsigned int)one_pkt[32];
        dst_ip_4th_digit = (unsigned int)one_pkt[33];

        if (dst_ip_1st_digit == 192 && dst_ip_2nd_digit == 11 && dst_ip_3rd_digit == 68 && dst_ip_4th_digit == 196) {
            one_pkt[30] = 192;
            one_pkt[31] = 11;
            one_pkt[32] = 68;
            one_pkt[33] = 1;
        }

        if (src_ip_1st_digit == 192 && src_ip_2nd_digit == 11 && src_ip_3rd_digit == 68 && src_ip_4th_digit == 196) {
            one_pkt[26] = 192;
            one_pkt[27] = 11;
            one_pkt[28] = 68;
            one_pkt[29] = 1;
        }

        if (!feof(fd_in)) {
            fwrite(pkt_header, sizeof(unsigned int), 4, fd_out);
            fwrite(one_pkt, sizeof(unsigned char), captured_len, fd_out);
        }
    }

    fclose(fd_in);
    fclose(fd_out);
}

// Struct to hold the session data
struct tcp_session_data {
    int session_count;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    int num_packets_sent;
    uint32_t session_through_bytes;
    uint32_t session_goodput_bytes;
    double session_start_time;
    double session_end_time;
};

// Function to reset the struct (when the session is finished)
void reset_tcp_session_data(struct tcp_session_data* session) {
    //session->session_count = 0;
    memset(session->src_ip, 0, sizeof(session->src_ip));
    memset(session->dst_ip, 0, sizeof(session->dst_ip));
    session->src_port = 0;
    session->dst_port = 0;
    session->num_packets_sent = 0;
    session->session_through_bytes = 0;
    session->session_goodput_bytes = 0;
    session->session_start_time = 0;
    session->session_end_time = 0;
}

// Function to print the session data (when the session is finished)
void print_tcp_session_data(FILE* fd_out, struct tcp_session_data* session) {
    // Round the sessionDuration and other values to 4 significant figures (example)
    double sessionDuration = (session->session_end_time - session->session_start_time);
    double rounded_sessionDuration = round_to_sig_figs(sessionDuration, 4);
    double rounded_throughput = round_to_sig_figs(session->session_through_bytes * 8 / sessionDuration, 10);
    double rounded_goodput = round_to_sig_figs(session->session_goodput_bytes * 8 / sessionDuration, 10);
    
    fprintf(fd_out, "%d\t", session->session_count);
    fprintf(fd_out, "%s\t%s\t", session->src_ip, session->dst_ip);
    fprintf(fd_out, "%d\t%d\t", session->src_port, session->dst_port);
    fprintf(fd_out, "%d\t%d\t%d\t", session->num_packets_sent, session->session_through_bytes, session->session_goodput_bytes);
    fprintf(fd_out, "%.4f\t", rounded_sessionDuration);
    fprintf(fd_out, "%f\t", rounded_throughput);
    fprintf(fd_out, "%f\t\n", rounded_goodput);
    //fprintf(fd_out, "%f\t%f\n", session->session_start_time, session->session_end_time);
}


void tcp_analysis(char *in_filename, char *out_filename)
{
    // Variables to store
    double session_start_time;
    double session_end_time;
    double session_duration;

    int src_port_num;
    int dst_port_num;
    char src_port_num_char[2];
    char dst_port_num_char[2];

    unsigned int ip_header_length;
    int source_ip;
    int destination_ip;
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];

    int TCP_session_count = 0;
    uint8_t next_header_protocol;
    int session_initiated = 0;
    int pointer_advancement = 0;
    int num_packets_sent = 0;
    int first_packet = 0;
    double time_zero;
    uint32_t session_through_bytes =0;
    uint32_t session_goodput_bytes =0;
    int frame_number = 0;

    char* tcp_server;
    char* tcp_client;

    struct tcp_session_data session;

    // valid sender IPs
    const char *allowed_src_ips[] = {
        "10.168.207.106",
        "10.168.207.107",
        "10.168.207.108",
        "10.168.207.109"
    };

    const char *allowed_dst_ips[] = {
        "192.11.68.196",
    };

    FILE *fd_in, *fd_out;
    // open the input file
    fd_in = fopen(in_filename, "r");
    if (fd_in == NULL) {
        perror("Error opening input file");
        return;
    }

    // open the output file
    fd_out = fopen(out_filename, "w");
    if (fd_out == NULL) {
        perror("Error opening output file");
        fclose(fd_in);  // Close the input file before returning
        return;
    }    

    // print the header for the output file
    fprintf(fd_out, "TCP_session_count, serverIP, clientIP, serverPort, clientPort, num_of_packetSent(server->client), "
                    "TotalIPtrafficBytesSent(server->client), TotaluserTrafficBytesSent(server->client), sessionDuration, "
                    "bps_IPlayerThroughput(server->client), bps_Goodput(server->client), frame_number (Wireshark)\n");
    fprintf(fd_out, "=========================================================================================================================\n");    

    // read file header
    struct pcap_file_header file_header;
    fread(&file_header, sizeof(struct pcap_file_header),1, fd_in);

    while (1) {
        // read one packet header
        struct pcap_pkthdr pkt_header;
        if (fread(&pkt_header, sizeof(struct pcap_pkthdr), 1, fd_in) != 1) {
            if (feof(fd_in)) {
                break; // End of file reached, exit loop
            } else {
                perror("Error reading packet header");
                break;
            }
        }
        if (first_packet == 0) {
            time_zero = pkt_header.time_usec;
            first_packet = 1;
        }
        frame_number += 1;

        // extract capture_length info
        int caplen = pkt_header.caplen;
        uint16_t total_ip_length = 0;

        // extract ethernet header
        struct ethernet_header eheader;
        fread(&eheader, sizeof(struct ethernet_header), 1, fd_in);
        unsigned int ethernet_header_length = sizeof(struct ethernet_header);
        pointer_advancement += ethernet_header_length;

        if (ntohs(eheader.ethertype) == 0x0800 || ntohs(eheader.ethertype) == 0x86DD) { 
            if (ntohs(eheader.ethertype) == 0x0800) { // IPv4 packet
                struct ipv4_header ip_header;
                if (fread(&ip_header, sizeof(struct ipv4_header), 1, fd_in) != 1) {
                    perror("Error reading IPv4 header");
                    break;
                }
                // Calculate actual IP header length from the version_ihl field (bottom 4 bits)
                ip_header_length = (ip_header.version_ihl & 0x0F) * 4;

                total_ip_length = ntohs(ip_header.total_length);

                // Check if there are options (i.e., if the actual IP header length is greater than the standard size)
                if (ip_header_length > sizeof(struct ipv4_header)) {
                    unsigned int option_length = ip_header_length - sizeof(struct ipv4_header);

                    // Advance the pointer to skip over the IP options
                    if (fseek(fd_in, option_length, SEEK_CUR) != 0) {
                        perror("Error skipping IP options");
                        break;
                    }
                }
                // Convert source and destination IPs from uint32 to string
                uint32_to_ip(ip_header.source_ip, src_ip_str);  // Update src_ip_str with IPv4 address
                uint32_to_ip(ip_header.destination_ip, dst_ip_str);  // Update dst_ip_str with IPv4 address
                next_header_protocol = ip_header.protocol;

            } else if (ntohs(eheader.ethertype) == 0x86DD) { // If IPv6 packet
                struct ipv6_header ipv6_hdr;
                if (fread(&ipv6_hdr, sizeof(struct ipv6_header), 1, fd_in) != 1) {
                    perror("Error reading IPv6 header");
                    break;
                }
                ip_header_length = sizeof(struct ipv6_header); // fixed header length
                total_ip_length = ip_header_length + ntohs(ipv6_hdr.payload_length);

                // Convert the source and destination IPv6 addresses to string format
                inet_ntop(AF_INET6, ipv6_hdr.source_ip, src_ip_str, sizeof(src_ip_str));  // IPv6 source address
                inet_ntop(AF_INET6, ipv6_hdr.destination_ip, dst_ip_str, sizeof(dst_ip_str));  // IPv6 destination address
            }

            pointer_advancement += ip_header_length;
            
            // check if source is valid IP
            unsigned int ip_valid = 0;
            for (int i = 0; i < 4; i++) {
                // Compare the string representation of the source IP with the allowed IPs
                if (strcmp(src_ip_str, allowed_src_ips[i]) == 0) {
                    ip_valid = 1;
                    num_packets_sent += 1;
                    break; // IP found, no need to continue the loop
                }
            }

            ip_valid &= !strcmp(dst_ip_str, allowed_dst_ips[0]);

            if (next_header_protocol == TCP_TYPE_NUM && ip_valid) {
                struct tcp_header tcpheader;
                if (fread(&tcpheader, sizeof(struct tcp_header), 1, fd_in) != 1) {
                    perror("Error reading TCP header");
                    break;
                }

                unsigned int standard_tcp_header_length = sizeof(struct tcp_header);  // Should be 20 bytes
                unsigned int tcp_header_length = ((tcpheader.data_offset >> 4) & 0x0F) * 4;

                // Check if there are options (i.e., if the actual TCP header length is greater than the standard size)
                if (tcp_header_length > standard_tcp_header_length) {
                    unsigned int option_length = tcp_header_length - standard_tcp_header_length;

                    // Advance the pointer to skip over the TCP options
                    if (fseek(fd_in, option_length, SEEK_CUR) != 0) {
                        perror("Error skipping TCP options");
                        break;
                    }
                }

                pointer_advancement += tcp_header_length;
                unsigned int total_header_length = ethernet_header_length + ip_header_length + tcp_header_length;
                unsigned int payload_length = caplen - total_header_length;
                unsigned int length = pkt_header.caplen;

                // On SYN flag, start session
                if ((tcpheader.flags & TCP_FLAG_SYN) && !session_initiated) {
                    session_initiated = 1;
                    session.session_count++;
                    strcpy(session.src_ip, src_ip_str);
                    strcpy(session.dst_ip, dst_ip_str);
                    session.src_port = ntohs(tcpheader.source_port);
                    session.dst_port = ntohs(tcpheader.destination_port);
                    session.session_start_time = pkt_header.time_sec + pkt_header.time_usec / 1000000.0;
                }

                if (session_initiated) {
                    // Print TCP session
                    if (strcmp(session.dst_ip, dst_ip_str) == 0 && strcmp(session.src_ip, src_ip_str) == 0) {
                        session.num_packets_sent++;
                        session.session_through_bytes += total_ip_length;
                        session.session_goodput_bytes += payload_length;
                    }


                    // On FIN flag, end session and print the cached data
                    if (tcpheader.flags & TCP_FLAG_FIN) {
                        session.session_end_time = pkt_header.time_sec + pkt_header.time_usec / 1000000.0;
                        print_tcp_session_data(fd_out, &session);
                        reset_tcp_session_data(&session); // Reset for the next session
                        session_initiated = 0;
                    }

                }

                next_header_protocol = 0;
            } 

        } 

        int bytes_left = caplen - pointer_advancement;
        if (bytes_left > 0) {
            if (fseek(fd_in, bytes_left, SEEK_CUR) != 0) {
                perror("Error seeking to next packet");
                break;
            }
        }
        pointer_advancement = 0;

} // end of WHILE loop

// Close files
fclose(fd_in);
fclose(fd_out);

}

int main(int argc, char* argv[])
{
    printf("Selected Option: %s\n", argv[1]);

    if (strcmp(argv[1], "ping-delay") == 0) {
        ping_response_time_finder(argv[2]);
    }
    else if (strcmp(argv[1], "fix-length") == 0) {
        fix_frame_len(argv[2], argv[3]);
    }
     else if (strcmp(argv[1], "ip-address-change") == 0) {
        ip_address_change(argv[2], argv[3]);
    }
    else if (strcmp(argv[1], "tcp-analysis") == 0) {
        // call your function
        tcp_analysis(argv[2], argv[3]);
    }
    else {
        printf("Four options are available.\n");
        printf("===== Four command line format description =====\n");
        printf("1:  ./pcap-analysis ping-delay input-trace-filename\n");
        printf("2:  ./pcap-analysis fix-length input-trace-filename output-trace-filename\n");
        printf("3:  ./pcap-analysis ip-address-change input-trace-filename output-trace-filename\n");
        printf("4:  ./pcap-analysis tcp-analysis  input-trace-filename  output-filename\n");
        printf("===== END =====\n");
    }
} /*end prog */


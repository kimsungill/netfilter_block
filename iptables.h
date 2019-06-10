#include <stdio.h>

struct ip_header{
    unsigned char ip_ver_len;
    unsigned char ip_ser_type;
    unsigned short ip_pac_len;
    unsigned short ip_ident;
    unsigned short ip_offset;
    unsigned char ip_live;
    unsigned char ip_tran;
    unsigned short ip_hea_sum;
    unsigned int ip_s_address;
    unsigned int ip_d_address;
};

struct tcp_header{
    unsigned short tcp_s_port;
    unsigned short tcp_d_port;
    unsigned int tcp_seq_num;
    unsigned int tcp_ack_num;
    unsigned char tcp_offset_res;
    unsigned char tcp_flags;
    unsigned short tcp_win_size;
    unsigned short tcp_checksum;
    unsigned short tcp_urg_pointer;
};

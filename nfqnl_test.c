#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include "iptables.h"
#include <string.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *input;
/* returns packet id */

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }

    struct ip_header *ip_h = (struct ip_header *)buf;
    unsigned short ip_len = ((ip_h->ip_ver_len) & 0x0F) * 4;                    // ok 20
    struct tcp_header *tcp_h = (struct tcp_header *)((uint8_t *)ip_h+ip_len);
    unsigned short tcp_len = ((tcp_h->tcp_offset_res) >> 4) * 4;                // ok 20
    unsigned char *http_start = ((unsigned char *)tcp_h+tcp_len);
    unsigned short http_len = (ntohs(ip_h->ip_pac_len)-ip_len-tcp_len);         // ok 341
    bool http_bool = false;
    bool host_bool = false;
    bool url_bool = false;
    unsigned int http_len_host;

    //-----------------------------------------------------------------------------------------------------
    //http start check ~
    printf("\n------------test-------------\n");
    const char* str_check[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
    for (int i = 0; i < 6; i++){
        if (strncmp((const char* )http_start,str_check[i],strlen(str_check[i])) == 0){
            http_bool = true;
            if(http_bool == 1){
                printf("-->Success! %s find!\n", str_check[i]);
                break;
            }
        }
    }
    if (http_bool == 0)
        printf("-->Failure! Can't find String\n");                              // ok
    //-----------------------------------------------------------------------------------------------------
    //http host check ~
    const char* str_check2 = "Host:";
    if (http_bool == 1){
        for(int i = 0; i < http_len; i++){
            if (memcmp((const char*)http_start+i, str_check2,5) == 0){
                http_len_host = i;
                host_bool = true;
                if(host_bool == 1){
                    printf("-->Success! Host find!\n");

                } else if (host_bool == 0){
                    printf("-->Failure! Can't find String\n");
                }
            }
        }
    }                                                                           // ok
    //-----------------------------------------------------------------------------------------------------
    //URL check ~
    if(host_bool == 1){
        for(int i = http_len_host; i < http_len; i++){
            if(memcmp((const char*)http_start+i,input,strlen(input)) == 0){
                url_bool = true;
                if(url_bool == 1){
                    printf("-->Success! %s same!\n",input);
                    break;
                } else if (url_bool == 0){
                    printf("-->Failure! %s different!\n",input);
                }
            }
        }
    }
    printf("------------test-------------\n\n");                                // ok
    //-----------------------------------------------------------------------------------------------------
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);
    dump(data, ret);

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
    input = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
                                 * are sent from kernel-space, the socket buffer that we use
                                 * to enqueue packets may fill up returning ENOBUFS. Depending
                                 * on your application, this error may be ignored. Please, see
                                 * the doxygen documentation of this library on how to improve
                                 * this situation.
                                 */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
                         * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

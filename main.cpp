#include <iostream>
#include <pcap.h>
#include <cstring>
#include "openssl/evp.h"
#include "./src/base64.h"
#include "./src/heard.h"
#include "./src/confusion.h"
#include "./src/protocol.h"
#include "./src/main.h"
#include "./src/ip_tcp.h"


using namespace std;

void packet_decode(anti_info *priori, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    unsigned int pkt_len = 0;
    Net net(priori->dst_port, (unsigned char *) pkt_data, &pkt_len);
    if (pkt_len == 0) {
        return;
    }
    uf *tmp_data = new uf[65535];
    uf4 tmp_data_len = 0;
    memcpy(tmp_data, pkt_data + ETH_LEN + net.u_ip.header_len + net.u_tcp.header_len, pkt_len);
    tmp_data_len = pkt_len;
    if (net.Direction == S2D) {
        int a = 0;
        if (priori->conf == http_simple || priori->conf == http_post) {
            a = priori->EI_up.hp.remove_f(tmp_data, &tmp_data_len);
        } else {
            a = priori->EI_up.ts.remove_f(tmp_data, &tmp_data_len);
        }
        if (!a) {
            cout << "1:this exist a pkt what do not need to remove confuse!" << endl;
            return;
        }
        priori->enc_data(&(priori->EI_up), tmp_data, &tmp_data_len);
        priori->remove_confuse(priori->rc4_key, &(priori->EI_up), tmp_data, &tmp_data_len);
    } else {
        int a = 0;
        if (priori->conf == http_simple || priori->conf == http_post) {
            a = priori->EI_dn.hp.remove_d(tmp_data, &tmp_data_len);
        } else {
            a = priori->EI_dn.ts.remove_f(tmp_data, &tmp_data_len);
        }
        if (!a) {
            cout << "2:this exist a pkt what do not need to remove confuse!" << endl;
            return;
        }
        if (priori->EI_dn.pkt_num == 1) {
            priori->EI_dn.cn->Init_hash(priori->EI_up.cn->last_server_hash);
        }
        priori->enc_data(&(priori->EI_dn), tmp_data, &tmp_data_len);
        priori->remove_confuse(priori->rc4_key, &(priori->EI_dn), tmp_data, &tmp_data_len);
    }
    delete tmp_data;
}

//处理每一包的入口函数
void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    anti_info *priori = (anti_info *) param;
    /*
    cout << "pwd is :" << priori->pwd <<endl;
    cout << "enc is :" << enc_str.find(priori->enc)->second << endl;
    cout << "dst_port is :" << priori->dst_port <<endl;
    cout << "pro is :" << pro_str.find(priori->pro)->second <<endl;
    cout << "pro_param is :" << priori->pro_param <<endl;
    cout << "conf is :" << conf_str.find(priori->conf)->second <<endl;
    cout << "conf_param is :" << priori->conf_param <<endl;
    */
    packet_decode(priori, header, pkt_data);
}

int main() {

    const char *path = "../ssr-file/chain_a/test.pcap";
    //aes128_md5|sha1_v4|aes128_sha1|verify_deflate|auth_chain_a|

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = NULL;
    handle = pcap_open_offline(path, errbuf);
    if (handle == NULL) {
        cout << errbuf << endl;
        return 0;
    }

    //初始化解密参数
    struct Init_info priori_kwl = {0};

    //
    priori_kwl.dst_port = 34657;
    priori_kwl.pwd = "123456";
    priori_kwl.conf = http_simple;
    priori_kwl.enc = aes_256_cfb;
    priori_kwl.conf_param = "";
    priori_kwl.pro = auth_chain_a;
    priori_kwl.pro_param = "";
    //


    anti_info AI(priori_kwl);
    int a = pcap_loop(handle, -1, packet_handler, (u_char *) &AI);
    if (a == 0) {
        printf("CNT is exhausted or no more packets are available from saved file.\n");
        return 0;
    } else if (a == -1) {
        printf("An error has occured from pcap_loop.\n");
        return -1;
    } else if (a == -2) {
        printf("Loop terminated due to a call to pcap_breakloop() before any packets were processed.\n");
        return -1;
    }
    return -1;
}


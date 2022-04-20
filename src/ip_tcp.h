#define MAC_LEN 6
#define ETH_LEN 14

enum Trans_Pro{
    TCP = 6,
    UDP = 17,
};

enum Stream_Dir{
    S2D,            //src to dst
    D2S,
};

struct eth {
    uf Des_Mac[MAC_LEN];
    uf Src_Mac[MAC_LEN];
    uf IPv[2];
};

#define IPv4_LEN 4

struct ip {
    uf version;
    uf header_len;
    uf diff_server_field;
    uf2 total_len;
    uf2 identification;
    uf flags[2];
    uf time2live;
    uf pro_type;
    uf header_checksum[2];
    uf Src_IP[IPv4_LEN];
    uf Dst_IP[IPv4_LEN];
} IPv4;

struct tcp {
    uf2 src_port;
    uf2 dst_port;
    uf4 Sequence_num;
    uf4 Acknowledgment_num;
    uf header_len;
    uf2 flags;
    uf2 window_size_value;
    uf2 checksum;
    uf2 urgent_pointer;
};




class Net{
public:
    struct eth u_eth;
    struct ip u_ip;
    struct tcp u_tcp;
    unsigned int Direction;
    Net(uf2 port,unsigned char* data,unsigned int * data_len);
    void get_eth_info(const unsigned char* data);
    void get_ip_info(const unsigned char* data);
    void get_tcp_info(const unsigned char* data);
};

void Net::get_eth_info(const unsigned char *data) {
    memcpy(u_eth.Des_Mac, data, MAC_LEN);
    memcpy(u_eth.Src_Mac, data + MAC_LEN, MAC_LEN);
    memcpy(u_eth.IPv, data + 2 * MAC_LEN, 2);
}

void Net::get_ip_info(const unsigned char *data) {
    u_ip.version = data[0] >> 4;
    u_ip.header_len = (data[0] & 0x0f) * 4;
    u_ip.diff_server_field = data[1];
    u_ip.total_len = data[2] * 256 + data[3];
    u_ip.identification = data[4] * 256 + data[5];
    memcpy(u_ip.flags, data + 6, 2);
    u_ip.time2live = data[8];
    u_ip.pro_type = data[9];
    memcpy(u_ip.header_checksum, data + 10, 2);
    memcpy(u_ip.Src_IP, data + 12, 4);
    memcpy(u_ip.Dst_IP, data + 16, 4);
}

void Net::get_tcp_info(const unsigned char *data) {
    u_tcp.src_port = data[0] * 256 + data[1];
    u_tcp.dst_port = data[2] * 256 + data[3];
    u_tcp.Sequence_num = chararray2int<uf4>((unsigned char *) (data + 4), 1);
    u_tcp.Acknowledgment_num = chararray2int<uf4>((unsigned char *) (data + 8), 1);
    u_tcp.header_len = (data[12] >> 4) * 4;
    u_tcp.flags = (data[12] & 0x0f) * 256 + data[13];
    u_tcp.window_size_value = chararray2int<uf2>((unsigned char *) (data + 14), 1);
    u_tcp.checksum = chararray2int<uf2>((unsigned char *) (data + 16), 1);
    u_tcp.urgent_pointer = chararray2int<uf2>((unsigned char *) (data + 18), 1);
}

Net::Net(uf2 port,unsigned char *data,unsigned int* data_len) {
    get_eth_info(data);
    data += ETH_LEN;
    get_ip_info(data);
    data += u_ip.header_len;
    if(u_ip.pro_type == TCP){
        get_tcp_info(data);
        data += u_tcp.header_len;
        *data_len = u_ip.total_len - u_ip.header_len - u_tcp.header_len;
        if(u_tcp.dst_port == port){
            Direction = S2D;
        }else{
            Direction = D2S;
        }
    }
}
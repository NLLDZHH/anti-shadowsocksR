#include <cstring>
#include "openssl/evp.h"
#include "openssl/md5.h"
#include "sodium/crypto_stream_chacha20.h"

struct Init_info {
    uf2 dst_port;
    const char *pwd;
    uf4 enc;
    const char *pro_param;
    uf4 pro;
    const char *conf_param;
    uf4 conf;
};


struct ENC_INFO {
    HTTP hp;
    TLS ts;

    uf4 flag;
    EVP_CIPHER_CTX *ctx;
    int plain;
    const EVP_CIPHER *cipher;
    uf IV[16];
    uf4 count;

    uf4 dir;
    uf4 pkt_num;
    ORIGIN *on;
    VERIFY_DEFLATE *vd;
    SHA1_V4 *sv;
    AES128 *a1;
    CHAIN *cn;
};

class anti_info {

public:

    //基本参数
    uf2 dst_port;
    const char *pwd;
    uf4 enc;
    const char *pro_param;
    uf4 pro;
    const char *conf_param;
    uf4 conf;


    uf enc_key[ENC_KEY];
    uf4 key_len;
    uf4 IV_len;
    struct ENC_INFO EI_up;
    struct ENC_INFO EI_dn;
    uf rc4_key[16];


    anti_info(struct Init_info pt);

    ~anti_info();

    void set_param(struct Init_info pt);

    void set_enc_model(uf4 enc);

    void enc_data(struct ENC_INFO *EI, uf *data, uf4 *dl);

    void chacha20dec(struct ENC_INFO *EI, uf *data, uf4 *dl);

    void remove_confuse(uf *rc4_key, struct ENC_INFO *EI, uf *data, uf4 *dl);
};

anti_info::anti_info(struct Init_info pr) {
    this->set_param(pr);
    this->set_enc_model(this->enc);

    //computer key
    pwd = pr.pwd;
    uf data_l[100] = {0};
    MD5_CTX md5_1;
    MD5_Init(&md5_1);
    MD5_Update(&md5_1, pwd, strlen(pwd));
    MD5_Final(data_l, &md5_1);
    memcpy(enc_key, data_l, 16);

    memcpy(data_l + 16, pwd, strlen(pwd));
    uf data_r[16] = {0};
    MD5_CTX md5_2;
    MD5_Init(&md5_2);
    MD5_Update(&md5_2, data_l, 16 + strlen(pwd));
    MD5_Final(data_r, &md5_2);
    memcpy(enc_key + 16, data_r, 16);

    // init the length of IV and key
    if (this->enc == chacha20) {
        IV_len = 8;
    } else {
        IV_len = 16;
    }
    if (this->enc <= aes_256_cfb) {
        key_len = 8 * (this->enc % 4 + this->enc / 4 + 1);
    } else if (this->enc == chacha20) {
        key_len = 32;
    } else if (this->enc == rc4) {
        key_len = 16;
    }
    // flag = 0 means the first pkt
    EI_up.flag = 0;
    EI_up.count = 0;
    EI_up.dir = 0;
    EI_up.pkt_num = 0;
    EI_up.on = new ORIGIN();
    EI_up.vd = new VERIFY_DEFLATE();
    EI_up.sv = new SHA1_V4();
    EI_up.a1 = new AES128(pr.pro, (uf *) pr.pro_param, strlen(pr.pro_param), this->enc_key, this->key_len);
    EI_up.cn = new CHAIN(pr.pro, (uf *) pr.pro_param, strlen(pr.pro_param), this->enc_key, this->key_len, this->IV_len);


    EI_dn.flag = 0;
    EI_dn.count = 0;
    EI_dn.dir = 1;
    EI_dn.pkt_num = 1;
    EI_dn.on = new ORIGIN();
    EI_dn.vd = new VERIFY_DEFLATE();
    EI_dn.sv = new SHA1_V4();
    EI_dn.a1 = new AES128(pr.pro, (uf *) pr.pro_param, strlen(pr.pro_param), this->enc_key, this->key_len);
    EI_dn.cn = new CHAIN(pr.pro, (uf *) pr.pro_param, strlen(pr.pro_param), this->enc_key, this->key_len, this->IV_len);
}

anti_info::~anti_info() {
    delete EI_up.cn;
    delete EI_up.a1;
    delete EI_up.sv;
    delete EI_up.vd;
    delete EI_up.on;

    delete EI_dn.cn;
    delete EI_dn.a1;
    delete EI_dn.sv;
    delete EI_dn.vd;
    delete EI_dn.on;
}

void anti_info::set_param(struct Init_info pr) {
    dst_port = pr.dst_port;
    enc = pr.enc;
    pro_param = pr.pro_param;
    pro = pr.pro;
    conf_param = pr.conf_param;
    conf = pr.conf;
}

void anti_info::set_enc_model(uf4 enc) {
    switch (enc) {
        case aes_128_ctr:
            EI_up.cipher = EVP_aes_128_ctr();
            EI_dn.cipher = EVP_aes_128_ctr();
            break;
        case aes_192_ctr:
            EI_up.cipher = EVP_aes_192_ctr();
            EI_dn.cipher = EVP_aes_192_ctr();
            break;
        case aes_256_ctr:
            EI_up.cipher = EVP_aes_256_ctr();
            EI_dn.cipher = EVP_aes_256_ctr();
            break;
        case aes_128_cfb:
            EI_up.cipher = EVP_aes_128_cfb();
            EI_dn.cipher = EVP_aes_128_cfb();
            break;
        case aes_192_cfb:
            EI_up.cipher = EVP_aes_192_cfb();
            EI_dn.cipher = EVP_aes_192_cfb();
            break;
        case aes_256_cfb:
            EI_up.cipher = EVP_aes_256_cfb();
            EI_dn.cipher = EVP_aes_256_cfb();
            break;
        case chacha20:
            EI_up.cipher = EVP_chacha20();
            EI_dn.cipher = EVP_chacha20();
            break;
        case rc4:
            EI_up.cipher = EVP_rc4();
            EI_dn.cipher = EVP_rc4();
            break;
        default:
            EI_up.cipher = NULL;
            EI_dn.cipher = NULL;
            break;
    }
    EI_up.plain = 0;
    EI_dn.plain = 0;
    EI_up.ctx = EVP_CIPHER_CTX_new();
    EI_dn.ctx = EVP_CIPHER_CTX_new();
}

void anti_info::chacha20dec(struct ENC_INFO *EI, uf *data, uf4 *dl) {
    uf4 d_len = 0;
    if (!EI->flag) {
        memcpy(EI->IV, data, IV_len);
        *dl -= IV_len;
        EI->flag = 1;
        d_len = IV_len;
    }
    uf4 padding = EI->count % BLOCK_SIZE;
    uf4 buf_size = padding + *dl;
    uf *buf = new uf[buf_size * 2]{0};
    uf *m_padding = new uf[buf_size]{0};
    memcpy(m_padding + padding, data + d_len, *dl);
    //printf("1: %d\n",*dl + padding);
    //print(m_padding,buf_size,64);
    crypto_stream_chacha20_xor_ic(buf, m_padding, buf_size, EI->IV, EI->count / BLOCK_SIZE, enc_key);
    EI->count += *dl;

    memcpy(data, buf + padding, buf_size - padding);
    //printf("1: %d\n",*dl);
    //print(data,*dl,64);
    delete buf;
    delete m_padding;
}

void anti_info::enc_data(struct ENC_INFO *EI, uf *data, uf4 *dl) {
    if (enc == chacha20) {
        chacha20dec(EI, data, dl);
        return;
    }
    uf *data_out = new uf[1500]{0};
    uf4 d_len = 0;
    if (!(EI->flag)) {
        memcpy(EI->IV, data, IV_len);
        *dl -= IV_len;
        EI->flag = 1;
        EVP_CipherInit(EI->ctx, EI->cipher, enc_key, EI->IV, DEC);
        d_len = IV_len;
    }
    EVP_CipherUpdate(EI->ctx, data_out, &(EI->plain), data + d_len, *dl);
    memcpy(data, data_out, *dl);
    delete data_out;
}

void anti_info::remove_confuse(uf *rc4_key, struct ENC_INFO *EI, uf *data, uf4 *dl) {
    switch (pro) {
        case origin: {
            EI->on->remove_p(EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case verify_deflate: {
            EI->vd->remove_p(EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_sha1_v4: {
            EI->sv->remove_p(EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_aes128_md5: {
            EI->a1->remove_p(EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_aes128_sha1: {
            EI->a1->remove_p(EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_a: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_b: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_c: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_d: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_e: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        case auth_chain_f: {
            EI->cn->remove_p(EI->dir, rc4_key, EI->IV, &(EI->pkt_num), data, dl);
        }
            break;
        default:
            break;
    }
}

template<typename T>
T chararray2int(unsigned char *data, int type) {
    int len = sizeof(T);
    T a = 0;
    for (int i = 0; i < len; i++) {
        if (type) {
            a = a * 256 + data[i];
        } else {
            a = a * 256 + data[len - i - 1];
        }
    }
    return a;
}



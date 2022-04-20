#include "openssl/md5.h"
#include "openssl/sha.h"
#include "map"
using namespace std;
typedef unsigned char uf;
typedef unsigned short uf2;
typedef unsigned int uf4;
typedef unsigned long uf8;
typedef unsigned long long uf16;

#define ENC_KEY 32
#define DEC 0
#define ENC 1
#define BLOCK_SIZE 64

unsigned char *strstr_f(char *s1, char *s2, int l1,int l2) {
    if (!l2)
        return (unsigned char *) s1;
    while (l1 >= l2) {
        l1--;
        if (!memcmp(s1, s2, l2))
            return (unsigned char *) s1;
        s1++;
    }
    return NULL;
}

void MD5_F(uf* data, uf4 data_len,uf* out_data){
    MD5_CTX md5 = {0};
    MD5_Init(&md5);
    MD5_Update(&md5,data,data_len);
    MD5_Final(out_data,&md5);
}

void SHA1_F(uf* data,uf4 data_len, uf* out_data){
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1,data,data_len);
    SHA1_Final(out_data,&sha1);
}

void print(unsigned char * data,int dl,int low){
    for(int i = 0;i<dl;i++){
        printf("%02x ",data[i]);
        if((i+1)%low == 0){
            printf("\n");
        }
    }
    printf("\n");
}

void Password_conversion(unsigned char* pwd, int pwd_len, unsigned char* key) {
    unsigned char inputmd5[100] = { 0 };
    unsigned int inputlen = 0;
    unsigned char encryptmd5[16] = { 0 };
    memcpy(inputmd5, pwd, pwd_len);
    inputlen = pwd_len;
    MD5_CTX md5_1;
    MD5_CTX md5_2;
    MD5_Init(&md5_1);
    MD5_Update(&md5_1, inputmd5, inputlen);
    MD5_Final(encryptmd5, &md5_1);
    unsigned char key_1[16] = { 0 };
    memcpy(key_1, encryptmd5, 16);
    memcpy(inputmd5, key_1, 16);
    memcpy(inputmd5 + 16, pwd, pwd_len);
    inputlen = pwd_len + 16;
    MD5_Init(&md5_2);
    MD5_Update(&md5_2, inputmd5, inputlen);
    MD5_Final(encryptmd5, &md5_2);
    memcpy(key, key_1, 16);
    memcpy(key + 16, encryptmd5, 16);
}

enum enc_info {
    none,
    aes_128_ctr,
    aes_192_ctr,
    aes_256_ctr,
    aes_128_cfb,
    aes_192_cfb,
    aes_256_cfb,
    rc4,
    rc4_md5,
    rc4_md5_6,
    salsa20,
    chacha20,
    xsalsa20,
    xchacha20,
    chacha20_ietf,
};

enum pro_info {
    origin,
    verify_deflate,
    auth_sha1_v4,
    auth_aes128_md5,
    auth_aes128_sha1,
    auth_chain_a,
    auth_chain_b,
    auth_chain_c,
    auth_chain_d,
    auth_chain_e,
    auth_chain_f,
};

enum conf_info {
    plain,
    http_simple,
    http_post,
    random_head,
    tls1_2_ticket_auth,
    tls1_2_ticket_fastauth,
};

static map<int, string> enc_str = {
        {none,          "none"},
        {aes_128_ctr,   "aes_128_ctr"},
        {aes_192_ctr,   "aes_192_ctr"},
        {aes_256_ctr,   "aes_256_ctr"},
        {aes_128_cfb,   "aes_128_cfb"},
        {aes_192_cfb,   "aes_192_cfb"},
        {aes_256_cfb,   "aes_256_cfb"},
        {rc4,           "rc4"},
        {rc4_md5,       "rc4_md5"},
        {rc4_md5_6,     "rc4_md5_6"},
        {salsa20,       "salsa20"},
        {chacha20,      "chacha20"},
        {xsalsa20,      "xsalsa20"},
        {xchacha20,     "xchacha20"},
        {chacha20_ietf, "chacha20_ietf"}
};
static map<int, string> pro_str = {
        {origin,           "origin"},
        {verify_deflate,   "verify_deflate"},
        {auth_sha1_v4,     "auth_sha1_v4"},
        {auth_aes128_md5,  "auth_aes128_md5"},
        {auth_aes128_sha1, "auth_aes128_sha1"},
        {auth_chain_a,     "auth_chain_a"},
        {auth_chain_b,     "auth_chain_b"},
        {auth_chain_c,     "auth_chain_c"},
        {auth_chain_d,     "auth_chain_d"},
        {auth_chain_e,     "auth_chain_e"},
        {auth_chain_f,     "auth_chain_f"}
};
static map<int, string> conf_str = {
        {plain,                  "plain"},
        {http_simple,            "http_simple"},
        {http_post,              "http_post"},
        {random_head,            "random_head"},
        {tls1_2_ticket_auth,     "tls1_2_ticket_auth"},
        {tls1_2_ticket_fastauth, "tls1_2_ticket_fastauth"}
};
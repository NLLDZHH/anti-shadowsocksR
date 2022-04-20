#include "zlib.h"
#include "openssl/hmac.h"

class ORIGIN {
public:
    ORIGIN();

    int remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl);
};

ORIGIN::ORIGIN() {}

int ORIGIN::remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl) {
    return 1;
}

#define VD_LEN 65535

class VERIFY_DEFLATE {
public:
    int flag;
    uf4 p_data_len;
    uf *data_p;
    uf4 data_p_len;

    VERIFY_DEFLATE();

    ~VERIFY_DEFLATE();

    int remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl);
};

VERIFY_DEFLATE::VERIFY_DEFLATE() {
    flag = 0;
    p_data_len = 0;
    data_p = new uf[VD_LEN];
    data_p_len = 0;
}

VERIFY_DEFLATE::~VERIFY_DEFLATE() {
    delete data_p;
}

int VERIFY_DEFLATE::remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl) {
    uf4 read_len = 0;
    uf *tmp_data = new uf[VD_LEN]{0};
    uf4 tmp_data_len = 0;
    while (read_len < *dl) {
        if (!flag) {
            p_data_len = (*data << 8) + *(data + 1);
            if (p_data_len > (*dl - read_len)) {
                memcpy(data_p, data + read_len, *dl - read_len);
                data_p_len = *dl - read_len;
                read_len = *dl;
                flag = 1;
            } else {
                memcpy(data_p, data + read_len, p_data_len);
                data_p_len = p_data_len;
                read_len += p_data_len;
            }
        } else {
            if ((p_data_len - data_p_len) > *dl) {
                memcpy(data_p + data_p_len, data, *dl);
                data_p_len += *dl;
                read_len = *dl;
            } else {
                memcpy(data_p + data_p_len, data, p_data_len - data_p_len);
                data_p_len = p_data_len;
                read_len = p_data_len - data_p_len;
                flag = 0;
            }
        }
        if (!flag) {
            data_p[0] = 0x78;
            data_p[1] = 0xda;
            z_stream inf;
            inf.zalloc = Z_NULL;
            inf.zfree = Z_NULL;
            inf.opaque = Z_NULL;
            inf.avail_in = (uInt) (data_p_len - 4);
            inf.next_in = (Bytef *) data_p;
            inf.avail_out = (uInt) VD_LEN;
            inf.next_out = (Bytef *) (tmp_data + tmp_data_len);
            inflateInit(&inf);
            inflate(&inf, Z_NO_FLUSH);
            inflateEnd(&inf);
            tmp_data_len += (VD_LEN - inf.avail_out);
        }
    }
    if (tmp_data_len != 0) {
        memcpy(data, tmp_data, tmp_data_len);
        *dl = tmp_data_len;
        delete tmp_data;
        return 1;
    }
    delete tmp_data;
    return 0;
}

#define SHA1_V4_LEN 65535

class SHA1_V4 {
public:
    uf4 p_data_len;
    uf *data_p;
    uf4 data_p_len;


    SHA1_V4();

    ~SHA1_V4();

    int remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl);
};

SHA1_V4::SHA1_V4() {
    p_data_len = 0;
    data_p = new uf[SHA1_V4_LEN]{0};
    data_p_len = 0;
}

SHA1_V4::~SHA1_V4() {
    delete data_p;
}

int SHA1_V4::remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl) {
    uf *tmp_data = new uf[SHA1_V4_LEN]{0};
    uf4 tmp_data_len = 0;
    memcpy(data_p + data_p_len, data, *dl);
    data_p_len += *dl;
    uf4 randlen = 0;
    while (1) {
        if (data_p_len == 0) {
            break;
        }
        p_data_len = (data_p[0] << 8) + data_p[1];
        if (p_data_len > data_p_len) {
            break;
        }
        if (*pkt_num == 0) {
            if (data_p[6] == 0xff) {
                randlen = (data_p[7] << 8) + data_p[8];
            } else {
                randlen = data_p[6];
            }
            memcpy(tmp_data + tmp_data_len, data_p + 2 + 4 + randlen + 4 + 4 + 4,
                   p_data_len - (2 + 4 + randlen + 4 + 4 + 4 + 10));
            tmp_data_len += p_data_len - (2 + 4 + randlen + 4 + 4 + 4 + 10);

            memcpy(data_p, data_p + p_data_len, data_p_len - p_data_len);

            data_p_len -= p_data_len;
            (*pkt_num)++;
        } else {
            if (data_p[4] == 0xff) {
                randlen = (data_p[5] << 8) + data_p[6];
            } else {
                randlen = data_p[4];
            }
            memcpy(tmp_data + tmp_data_len, data_p + 2 + 2 + randlen,
                   p_data_len - (2 + 2 + randlen + 4));
            tmp_data_len += p_data_len - (2 + 2 + randlen + 4);
            //printf("1:\n");
            //print(data_p,data_p_len,64);
            memcpy(data_p, data_p + p_data_len, data_p_len - p_data_len);
            //printf("2:\n");
            //print(data_p,data_p_len,64);
            data_p_len -= p_data_len;
            (*pkt_num)++;
        }
    }
    if (tmp_data_len == 0) {
        delete tmp_data;
        *dl = 0;
        cout << "the length of data is not enough!" << endl;
        return 0;
    } else {
        memcpy(data, tmp_data, tmp_data_len);
        *dl = tmp_data_len;
        delete tmp_data;
        return 1;
    }
}

#define AES128_LEN 65535
#define PARAM_LEN 32

class AES128 {
public:
    string SALT;
    uf4 p_data_len;
    uf4 randlen;
    uf *data_p;
    uf4 data_p_len;
    uf pro_param[PARAM_LEN];
    uf4 param_len;
    uf key[ENC_KEY];
    uf4 key_len;

    AES128(uf4 pro, uf *param, uf4 pl, uf *key_in, uf4 kl);

    ~AES128();

    char *_base64_encode(uf *data, uf4 dl);

    int remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl);
};

AES128::AES128(uf4 pro, uf *param, uf4 pl, uf *key_in, uf4 kl) {
    SALT = pro_str.find(pro)->second;
    p_data_len = 0;
    randlen = 0;
    data_p = new uf[AES128_LEN]{0};
    data_p_len = 0;
    memcpy(pro_param, param, pl);
    param_len = pl;
    memcpy(key, key_in, kl);
    key_len = kl;
}

AES128::~AES128() {
    delete data_p;
}

char *AES128::_base64_encode(uf *data, uf4 dl) {
    char *BASE64;
    uf4 bl;
    BASE64 = base64_encode((const char *) data, dl);
    uf4 a = strlen(BASE64) % 4;
    if (a == 3 || a == 1) {
        bl = 1;
    } else {
        bl = a;
    }
    for (int i = 0; i < bl; i++) {
        BASE64 = strcat(BASE64, "=");
    }
    return BASE64;
}

int AES128::remove_p(uf *iv, uf4 *pkt_num, uf *data, uf4 *dl) {
    uf4 only = 1 + 6 + 4 + 4 + 4 + 4 + 2 + 2;
    memcpy(data_p + data_p_len, data, *dl);
    data_p_len += *dl;
    //cout << "123:" << data_p_len << endl;
    //print(data_p,data_p_len,64);
    uf tmp_data[65535] = {0};
    uf4 tmp_data_len = 0;
    while (data_p_len > 0) {
        if (*pkt_num == 0) {
            if (p_data_len == 0) {
                p_data_len = only;
            }
            if (data_p_len < p_data_len) {
                break;
            }
            if (p_data_len == only) {
                //准备密文数据
                uf pro_dec_data[16] = {0};
                memcpy(pro_dec_data, data_p + 11, 16);

                //准备密钥
                uf KEY[16] = {0};
                uf sd[32] = {0};
                uf4 sd_len = 0;
                if (param_len != 0) {
                    SHA1_F(pro_param, param_len, sd);
                    sd_len = 20;
                } else {
                    memcpy(sd, key, key_len);
                    sd_len = key_len;
                }
                uf tmpkey[100] = {0};
                const char *base_s = (const char *) _base64_encode((uf *) sd, sd_len);
                memcpy(tmpkey, base_s, strlen(base_s));
                memcpy(tmpkey + strlen(base_s), SALT.c_str(), SALT.length());
                MD5_F(tmpkey, strlen(base_s) + SALT.length(), KEY);

                //IV
                uf IV[16] = {0};

                //解密
                uf plain[16] = {0};
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                const EVP_CIPHER *cipher = EVP_aes_128_cbc();
                int plainl = 0;
                EVP_CipherInit(ctx, cipher, KEY, IV, 0);
                EVP_CipherUpdate(ctx, plain, &plainl, pro_dec_data, 16);
                EVP_CIPHER_CTX_cleanup(ctx);
                EVP_CIPHER_CTX_free(ctx);
                //cout << "key:" << endl;
                //print(KEY, 16, 16);
                //cout << "plain:" << endl;
                //print(plain, 16, 16);




                //
                p_data_len = (plain[13] << 8) + plain[12];
                randlen = (plain[15] << 8) + plain[14];
                //cout << "123:" << p_data_len << " 234:" << randlen << endl;
                continue;
            }
        } else {
            p_data_len = (data_p[1] << 8) + data_p[0];
            if (data_p_len < p_data_len) {
                break;
            }
            if (data_p[4] == 0xff) {
                randlen = (data_p[6] << 8) + data_p[5];
            } else {
                randlen = data_p[4];
            }
        }
        uf4 head_len = 0;
        if (*pkt_num == 0) {
            head_len = only + 4 + randlen;
        } else {
            head_len = 2 + 2 + randlen;
        }
        memcpy(tmp_data + tmp_data_len, data_p + head_len, p_data_len - head_len - 4);
        tmp_data_len += p_data_len - head_len - 4;
        memcpy(data_p, data_p + p_data_len, data_p_len - p_data_len);
        data_p_len -= p_data_len;
        (*pkt_num)++;
    }
    memcpy(data, tmp_data, tmp_data_len);
    *dl = tmp_data_len;
    return 1;
}

class RAND_A {
public:
    uf key[ENC_KEY];
    uf4 key_len;
    uf2 Over_Head;
    uf4 TIME;
    uf4 randlen;
    uf4 randlen_pos;

    void set_param(uf *Key, uf4 kl, uf2 oh, uf4 time);

    uf16 next(uf16 *v0, uf16 *v1);

    void Init_from_bin(uf4 dl, uf *hash, uf16 *v0, uf16 *v1);

    int getrandstrpos(uf4 randlen, uf16 *v0, uf16 *v1);

    void get_randlen(uf *hash, uf4 dl);
};

void RAND_A::set_param(uf *Key, uf4 kl, uf2 oh, uf4 time) {
    memcpy(key, Key, kl);
    key_len = kl;
    Over_Head = oh;
    TIME = time;
}

uf16 RAND_A::next(uf16 *v0, uf16 *v1) {
    uf16 x = *v0;
    uf16 y = *v1;
    (*v0) = y;
    x ^= (x << 23);
    x ^= (y ^ (x >> 17) ^ (y >> 26));
    (*v1) = x;
    return x + y;
}

void RAND_A::Init_from_bin(uf4 dl, uf *hash, uf16 *v0, uf16 *v1) {
    int i;
    *v0 = 0;
    *v1 = 0;
    for (i = 7; i > 1; i--) {
        *v0 = (*v0 << 8) + hash[i];
    }
    (*v0) = (*v0 << 8) + (uf) (dl >> 8);
    (*v0) = (*v0 << 8) + (uf) dl;
    for (i = 15; i > 7; i--) {
        *v1 = (*v1 << 8) + hash[i];
    }
    for (i = 0; i < 4; ++i) {
        next(v0, v1);
    }
    return;
}

int RAND_A::getrandstrpos(uf4 randlen, uf16 *v0, uf16 *v1) {
    if (randlen > 0) {
        return (int) (next(v0, v1) % 8589934609 % randlen);
    }
    return 0;
}

void RAND_A::get_randlen(uf *hash, uf4 dl) {
    uf16 v0 = 0;
    uf16 v1 = 0;
    if (dl > 1440) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    Init_from_bin(dl, hash, &v0, &v1);
    int a = 0;
    if (dl > 1300) {
        a = 31;
    }else if (dl > 900) {
        a = 127;
    }else if (dl > 400) {
        a = 521;
    }else{
        a = 1021;
    }
    randlen = (uf4) (next(&v0, &v1) % a);
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

class RAND_B : public RAND_A {
public:
    int Find_Pos(int *dsl, int l, uf4 Ol);

    void sort(int *dsl, int l);

    void Init_from_bin_b(uf *key, uf16 *v0, uf16 *v1);

    void InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl1, int *l1, int *dsl2, int *l2);

    void get_randlen(uf *hash, uf4 dl);
};

int RAND_B::Find_Pos(int *dsl, int l, uf4 Ol) {
    int low = 0;
    int high = l - 1;
    int middle = -1;
    if (Ol < dsl[high]) {
        return l;
    }
    while (low < high) {
        middle = (low + high) / 2;
        if (Ol > dsl[middle]) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return low;
}

void RAND_B::Init_from_bin_b(uf *key, uf16 *v0, uf16 *v1) {
    int i;
    *v0 = 0;
    *v1 = 0;
    for (i = 7; i >= 0; i--) {
        *v0 = (*v0 << 8) + key[i];
    }
    for (i = 15; i > 7; i--) {
        *v1 = (*v1 << 8) + key[i];
    }
}

void RAND_B::sort(int *dsl, int l) {
    int i, j;
    for (i = 0; i < l - 1; i++) {
        for (j = 0; j < l - 1 - i; j++) {
            if (dsl[j] > dsl[j + 1]) {
                dsl[j] += dsl[j + 1];
                dsl[j + 1] = dsl[j] - dsl[j + 1];
                dsl[j] -= dsl[j + 1];
            }
        }
    }
}

void RAND_B::InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl1, int *l1, int *dsl2, int *l2) {
    int i;
    Init_from_bin_b(key, v0, v1);
    *l1 = (int) (next(v0, v1) % 8 + 4);
    for (i = 0; i < *l1; i++) {
        dsl1[i] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
    }
    sort(dsl1, *l1);
    *l2 = (int) (next(v0, v1) % 16 + 8);
    for (i = 0; i < *l2; i++) {
        dsl2[i] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
    }
    sort(dsl2, *l2);
}

void RAND_B::get_randlen(uf *hash, uf4 dl) {
    int len1, len2;
    int data_size_list1[12], data_size_list2[24];
    uf16 v0 = 0, v1 = 0;
    InitDataSizeList(&v0, &v1, data_size_list1, &len1, data_size_list2, &len2);
    if (dl >= 1440) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    uf dst_hash[16] = {0};
    memcpy(dst_hash, hash, 16);
    Init_from_bin(dl, dst_hash, &v0, &v1);
    int pos = Find_Pos(data_size_list1, len1, Over_Head + dl);
    int final_pos = pos + (int) (next(&v0, &v1) % len1);
    if (final_pos < len1) {
        randlen = data_size_list1[final_pos] - dl - Over_Head;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    pos = Find_Pos(data_size_list2, len2, dl + Over_Head);
    final_pos = pos + (int) (next(&v0, &v1) % len2);
    if (final_pos < len2) {
        randlen = data_size_list2[final_pos] - dl - Over_Head;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    if (final_pos < pos + len2 - 1) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    int a = 0;
    if (dl > 1300) {
        a = 31;
    }
    if (dl > 900) {
        a = 127;
    }
    if (dl > 400) {
        a = 521;
    } else {
        a = 1021;
    }
    randlen = (uf4) (next(&v0, &v1) % a);
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

class RAND_C : public RAND_B {
public:

    void InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl, int *l);

    void get_randlen(uf *hash, uf4 dl);
};

void RAND_C::InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl, int *l) {
    int i;
    Init_from_bin_b(key, v0, v1);
    *l = (int) (next(v0, v1) % (8 + 16) + 8 + 4);
    for (i = 0; i < *l; i++) {
        dsl[i] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
    }
    sort(dsl, *l);
}

void RAND_C::get_randlen(uf *hash, uf4 dl) {
    uf16 v0 = 0, v1 = 0;
    int data_size_list[36] = {0};
    int len;
    InitDataSizeList(&v0, &v1, data_size_list, &len);
    uf dst_hash[16] = {0};
    memcpy(dst_hash, hash, 16);
    Init_from_bin(dl, dst_hash, &v0, &v1);
    if ((dl + Over_Head) >= data_size_list[len - 1]) {
        if (dl > 1440) {
            randlen = 0;
            randlen_pos = getrandstrpos(randlen, &v0, &v1);
            return;
        }
        int a = 0;
        if (dl > 1300) {
            a = 31;
        }
        if (dl > 900) {
            a = 127;
        }
        if (dl > 400) {
            a = 521;
        } else {
            a = 1021;
        }
        randlen = (uf4) (next(&v0, &v1) % a);
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    int pos = Find_Pos(data_size_list, len, dl + Over_Head);
    int final_pos = pos + (int) (next(&v0, &v1) % (len - pos));
    randlen = data_size_list[final_pos] - dl - Over_Head;
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

class RAND_D : public RAND_C {
public:

    void CheckAndPatchDataSize(int *dsl, int *l, uf16 *v0, uf16 *v1);

    void InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl, int *l);

    void get_randlen(uf *hash, uf4 dl);
};

void RAND_D::CheckAndPatchDataSize(int *dsl, int *l, uf16 *v0, uf16 *v1) {
    if (dsl[*l - 1] < 1300 && *l < 64) {
        dsl[*l] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
        (*l)++;
        CheckAndPatchDataSize(dsl, l, v0, v1);
    }
}

void RAND_D::InitDataSizeList(uf16 *v0, uf16 *v1, int *dsl, int *l) {
    int i;
    Init_from_bin_b(key, v0, v1);
    *l = (int) (next(v0, v1) % (8 + 16) + 4 + 8);
    for (i = 0; i < *l; i++) {
        dsl[i] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
    }
    sort(dsl, *l);
    int old_l = *l;
    CheckAndPatchDataSize(dsl, l, v0, v1);
    if (old_l != *l) {
        sort(dsl, *l);
    }
}

void RAND_D::get_randlen(uf *hash, uf4 dl) {
    uf16 v0 = 0, v1 = 0;
    int data_size_list[64] = {0};
    int len;
    InitDataSizeList(&v0, &v1, data_size_list, &len);
    if ((dl + Over_Head) > data_size_list[len - 1]) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    uf dst_hash[16] = {0};
    memcpy(dst_hash, hash, 16);
    Init_from_bin(dl, dst_hash, &v0, &v1);
    int pos = Find_Pos(data_size_list, len, dl + Over_Head);
    int final_pos = pos + (int) (next(&v0, &v1) % (len - pos));
    randlen = data_size_list[final_pos] - dl - Over_Head;
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

class RAND_E : public RAND_D {
public:

    void get_randlen(uf *hash, uf4 dl);
};

void RAND_E::get_randlen(uf *hash, uf4 dl) {
    uf16 v0 = 0, v1 = 0;
    int data_size_list[64] = {0};
    int len;
    InitDataSizeList(&v0, &v1, data_size_list, &len);
    uf dst_hash[16] = {0};
    memcpy(dst_hash, hash, 16);
    Init_from_bin(dl, dst_hash, &v0, &v1);
    if ((dl + Over_Head) > data_size_list[len - 1]) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    int pos = Find_Pos(data_size_list, len, dl + Over_Head);
    randlen = data_size_list[pos] - dl - Over_Head;
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

class RAND_F : public RAND_E {
public:
    uf *param;
    uf4 param_len;
    uf16 Time;

    void Init_Interval(uf16 *Interval);

    void OnInitAuthData(uf16 Interval, uf *kcdkb);

    void InitDataSizeList(uf *kcdkb, int *dsl, int *l, uf16 *v0, uf16 *v1);

    void get_randlen(uf *hash, uf4 dl);
};

void RAND_F::Init_Interval(uf16 *Interval) {
    *Interval = 0;
    if (param_len == 0) {
        *Interval = 60 * 60 * 24;
    } else if (memchr(param, '#', param_len) == NULL) {
        for (int i = 0; i < param_len; i++) {
            *Interval = (*Interval << 8) + param[i];
        }
    } else {
        char *str = (char *) memchr(param, '#', param_len);
        for (int i = 1; i < strlen(str); i++) {
            *Interval = (*Interval << 8) + str[i];
        }
    }
    return;
}

void RAND_F::OnInitAuthData(uf16 Interval, uf *kcdkb) {
    uf16 key_change_datatime_key = Time / Interval;
    for (int i = 7; i >= 0; --i) {
        kcdkb[7 - i] = (char) (key_change_datatime_key >> (8 * i) & 0xff);
    }
    return;
}

void RAND_F::InitDataSizeList(uf *kcdkb, int *dsl, int *l, uf16 *v0, uf16 *v1) {
    uf n_key[32] = {0};
    memcpy(n_key, key, key_len);
    for (int i = 0; i < 8; i++) {
        n_key[i] ^= kcdkb[i];
    }
    Init_from_bin_b(n_key, v0, v1);
    *l = (int) (next(v0, v1) % (8 + 16) + (4 + 8));
    for (int i = 0; i < *l; ++i) {
        dsl[i] = (int) (next(v0, v1) % 2340 % 2040 % 1440);
    }
    sort(dsl, *l);
    int old_l = *l;
    CheckAndPatchDataSize(dsl, l, v0, v1);
    if (old_l != *l) {
        sort(dsl, *l);
    }
    return;
}

void RAND_F::get_randlen(uf *hash, uf4 dl) {
    uf16 v0 = 0, v1 = 0, Interval;
    Init_Interval(&Interval);
    uf key_change_datatime_key_bytes[8] = {0};
    OnInitAuthData(Interval, key_change_datatime_key_bytes);
    int data_size_list[64] = {0};
    int len;
    InitDataSizeList(key_change_datatime_key_bytes, data_size_list, &len, &v0, &v1);
    uf dst_hash[16] = {0};
    memcpy(dst_hash, hash, 16);
    Init_from_bin(dl, dst_hash, &v0, &v1);
    if ((dl + Over_Head) > data_size_list[len - 1]) {
        randlen = 0;
        randlen_pos = getrandstrpos(randlen, &v0, &v1);
        return;
    }
    int pos = Find_Pos(data_size_list, len, dl + Over_Head);
    randlen = data_size_list[pos] - dl - Over_Head;
    randlen_pos = getrandstrpos(randlen, &v0, &v1);
    return;
}

#define CHAIN_LEN 65535

class CHAIN {
public:
    string SALT;
    uf4 p_data_len;
    uf *data_p;
    uf4 data_p_len;
    uf last_hash[16];
    uf last_server_hash[16];
    uf pro_param[PARAM_LEN];
    uf4 param_len;
    uf4 IV_len;
    uf key[ENC_KEY];
    uf4 key_len;
    uf2 Over_Head;
    uf4 TIME;
    uf4 randlen;
    uf4 randlen_pos;

    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    int plainl;
    uf rc4_IV[16];
    //uf rc4_key[16];

    CHAIN(uf4 pro, uf *param, uf4 pl, uf *key_in, uf4 kl, uf4 IVl);

    ~CHAIN();

    int remove_p(uf4 dir, uf *rc4_key, uf *iv, uf4 *pkt_num, uf *data, uf4 *dl);

    void Init_hash(uf *hash);

    char *_base64_encode(uf *data, uf4 dl);

    void compute_cbc_key(uf *KEY);

    void compute_hash(uf *KEY, uf4 KL, uf *data, uf4 dl, uf *hash);

    void dec_cbc(uf *plain);

    void Init_rc4_key(uf *rc4_key);

    void dec_rc4(uf *rc4_key, uf4 pkt_num, uf *data, uf4 dl, uf *out_data);

    void int2char(int l, uf *out, uf4 *dl);

    void get_randlen(uf *hash, uf4 dl);
};

CHAIN::CHAIN(uf4 pro, uf *param, uf4 pl, uf *key_in, uf4 kl, uf4 IVl) {
    SALT = pro_str.find(pro)->second;
    p_data_len = 0;
    data_p = new uf[CHAIN_LEN]{0};
    data_p_len = 0;
    memcpy(pro_param, param, pl);
    param_len = pl;
    memcpy(key, key_in, kl);
    key_len = kl;
    IV_len = IVl;
    memset(last_hash, 0, 16);
    memset(last_server_hash, 0, 16);
}

CHAIN::~CHAIN() {
    delete data_p;
}

void CHAIN::compute_cbc_key(uf *KEY_K) {
    uf MD5_D[100] = {0};
    char *BASE64;
    if (param_len == 0) {
        BASE64 = _base64_encode(key, key_len);
    } else {
        BASE64 = _base64_encode(pro_param, param_len);
    }
    memcpy(MD5_D, BASE64, strlen(BASE64));
    memcpy(MD5_D + strlen(BASE64), SALT.c_str(), SALT.length());
    MD5_CTX ctx = {0};
    MD5_Init(&ctx);
    MD5_Update(&ctx, MD5_D, strlen(BASE64) + SALT.length());
    MD5_Final(KEY_K, &ctx);
}

void CHAIN::Init_hash(uf *hash) {
    memcpy(last_server_hash, hash, 16);
}

void CHAIN::dec_cbc(uf *plain) {
    uf KEY_K[16] = {0};
    compute_cbc_key(KEY_K);

    uf IV[16] = {0};

    EVP_CIPHER_CTX *ctx_d = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int plain_l = 0;
    EVP_CipherInit(ctx_d, cipher, KEY_K, IV, 0);
    EVP_CipherUpdate(ctx_d, plain, &plain_l, (const unsigned char *) (data_p + 16), 16);
    EVP_CIPHER_CTX_cleanup(ctx_d);
    EVP_CIPHER_CTX_free(ctx_d);
}

void CHAIN::compute_hash(uf *KEY, uf4 KL, uf *data, uf4 dl, uf *hash) {
    uf4 HASH_LEN = 0;
    HMAC(EVP_md5(), KEY, KL, data, dl, hash, &HASH_LEN);
}

void CHAIN::Init_rc4_key(uf *rc4_key) {
    uf *base1, *base2;
    if (param_len == 0) {
        base1 = (uf *) _base64_encode(key, key_len);
    } else {
        base1 = (uf *) _base64_encode(pro_param, param_len);
    }
    base2 = (uf *) _base64_encode(last_hash, 16);
    uf tmp_data[100] = {0};
    memcpy(tmp_data, base1, strlen((const char *) base1));
    memcpy(tmp_data + strlen((const char *) base1), base2, strlen((const char *) base2));
    uf4 tmp_len = strlen((const char *) base1) + strlen((const char *) base2);
    MD5_F(tmp_data, tmp_len, rc4_key);
}

void CHAIN::dec_rc4(uf *rc4_key, uf4 pkt_num, uf *data, uf4 dl, uf *out_data) {
    if (pkt_num == 1) {
        ctx = EVP_CIPHER_CTX_new();
        cipher = EVP_rc4();
        plainl = 0;
        memset(rc4_IV, 0, 16);
        EVP_CipherInit(ctx, cipher, rc4_key, rc4_IV, DEC);
    }
    EVP_CipherUpdate(ctx, out_data, &plainl, data, dl);
}

void CHAIN::get_randlen(uf *hash, uf4 dl) {
    if (SALT == pro_str.find(auth_chain_a)->second) {
        RAND_A RA;
        RA.set_param(key, key_len, Over_Head, TIME);
        RA.get_randlen(hash, dl);
        randlen = RA.randlen;
        randlen_pos = RA.randlen_pos;
    }
    if (SALT == pro_str.find(auth_chain_b)->second) {
        RAND_B RB;
        RB.set_param(key, key_len, Over_Head, TIME);
        RB.get_randlen(hash, dl);
        randlen = RB.randlen;
        randlen_pos = RB.randlen_pos;
    }
    if (SALT == pro_str.find(auth_chain_c)->second) {
        RAND_C RC;
        RC.set_param(key, key_len, Over_Head, TIME);
        RC.get_randlen(hash, dl);
        randlen = RC.randlen;
        randlen_pos = RC.randlen_pos;
    }
    if (SALT == pro_str.find(auth_chain_d)->second) {
        RAND_D RD;
        RD.set_param(key, key_len, Over_Head, TIME);
        RD.get_randlen(hash, dl);
        randlen = RD.randlen;
        randlen_pos = RD.randlen_pos;
    }
    if (SALT == pro_str.find(auth_chain_e)->second) {
        RAND_E RE;
        RE.set_param(key, key_len, Over_Head, TIME);
        RE.get_randlen(hash, dl);
        randlen = RE.randlen;
        randlen_pos = RE.randlen_pos;
    }
    if (SALT == pro_str.find(auth_chain_f)->second) {
        RAND_F RF;
        RF.set_param(key, key_len, Over_Head, TIME);
        RF.get_randlen(hash, dl);
        randlen = RF.randlen;
        randlen_pos = RF.randlen_pos;
    }
}

char *CHAIN::_base64_encode(uf *data, uf4 dl) {
    char *BASE64;
    uf4 bl;
    BASE64 = base64_encode((const char *) data, dl);
    uf4 a = strlen(BASE64) % 4;
    if (a == 3 || a == 1) {
        bl = 1;
    } else {
        bl = a;
    }
    for (int i = 0; i < bl; i++) {
        BASE64 = strcat(BASE64, "=");
    }
    return BASE64;
}

void CHAIN::int2char(int l, uf *out, uf4 *dl) {
    do {
        out[*dl] = l % 256;
        (*dl)++;
        l /= 256;
    } while (l != 0);
}

int CHAIN::remove_p(uf4 dir, uf *rc4_key, uf *iv, uf4 *pkt_num, uf *data, uf4 *dl) {
    uf tmp_data[65535] = {0};
    uf4 tmp_len = 0;
    memcpy(data_p + data_p_len, data, *dl);
    data_p_len += *dl;
    //cout << "FFF:" << endl;
    //print(data_p, data_p_len, 64);
    uf4 only = 4 + 8 + 4 + 4 + 4 + 4 + 2 + 2 + 4;
    if (*pkt_num == 0) {
        if (data_p_len < only) {
            return 0;
        } else {
            uf KEY[48] = {0};
            memcpy(KEY, iv, IV_len);
            memcpy(KEY + IV_len, key, key_len);
            compute_hash(KEY, IV_len + key_len, data, 4, last_hash);
            //cout << "last_hash:" << endl;
            //print(last_hash, 16, 16);
            compute_hash(key, key_len, data + 12, 20, last_server_hash);
            //cout << "last_server_hash:" << endl;
            //print(last_server_hash, 16, 16);
            Init_rc4_key(rc4_key);

            uf plain[16] = {0};
            dec_cbc(plain);

            TIME = 0;
            for (int i = 3; i > -1; i--) {
                TIME = (TIME << 8) + plain[i];
            }
            Over_Head = (plain[13] << 8) + plain[12];
        }
    }
    if (*pkt_num == 0) {
        memcpy(data_p, data_p + only, data_p_len - only);
        data_p_len -= only;
        (*pkt_num)++;
    }
    uf hash[16] = {0};
    if (!dir) {
        memcpy(hash, last_hash, 16);
    } else {
        memcpy(hash, last_server_hash, 16);
    }
    while (data_p_len > 0) {
        uf4 ture_len = ((data_p[1] << 8) + data_p[0]) ^((hash[15] << 8) + hash[14]);
        get_randlen(hash, ture_len);
        p_data_len = randlen + 2 + ture_len + 2;
        if (data_p_len < p_data_len) {
            break;
        }
        dec_rc4(rc4_key, *pkt_num, data_p + 2 + randlen_pos, p_data_len - randlen - 2 - 2, tmp_data + tmp_len);
        tmp_len += (p_data_len - randlen - 2 - 2);

        uf KEY_F[100] = {0};
        uf4 KL = 0;
        if (param_len == 0) {
            memcpy(KEY_F, key, key_len);
            KL = key_len;
        } else {
            memcpy(KEY_F, pro_param, param_len);
            KL = param_len;
        }
        int2char(*pkt_num, KEY_F, &KL);
        if (!dir) {
            compute_hash(KEY_F, KL, data_p, p_data_len - 2, last_hash);
        } else {
            compute_hash(KEY_F, KL, data_p, p_data_len - 2, last_server_hash);
        }

        memcpy(data_p, data_p + p_data_len, data_p_len - p_data_len);
        data_p_len -= p_data_len;
        (*pkt_num)++;
    }
    if (tmp_len != 0) {
        memcpy(data, tmp_data, tmp_len);
        *dl = tmp_len;
        return 1;
    } else {
        *dl = 0;
        cout << "the length of data do not enough!" << endl;
        return 0;
    }

}




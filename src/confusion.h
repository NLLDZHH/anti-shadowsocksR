#include <map>

const char *_request_path_[] = {
        "", "",
        "login.php?redir=", "",
        "register.php?code=", "",
        "?keyword=", "",
        "search?src=typd&q=", "&lang=en",
        "s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn=",
        "post.php?id=", "&goto=view.php",
};
const char *rnrn = "\r\n\r\n";
const char *get_post = " /";
const char *http = " HTTP/1.1\r\n";


class HTTP {
public:
    int flag;   //HTTP去混淆标识，1表示已完成去混淆，0表示未完成去混淆
    HTTP();

    int hex2int(const unsigned char c);

    void hex2char(const char *data, unsigned char *p_data, uf4 data_len);

    int remove_f(unsigned char *data, uf4 *dl);

    int remove_d(unsigned char *data, uf4 *dl);

};

HTTP::HTTP() {
    flag = 0;
}

int HTTP::hex2int(const unsigned char c) {
    if (c >= '0' and c <= '9') { return c - '0'; }
    if (c >= 'A' and c <= 'F') { return c - 'A' + 10; }
    if (c >= 'a' and c <= 'f') { return c - 'a' + 10; }
}

void HTTP::hex2char(const char *data, unsigned char *p_data, uf4 data_len) {
    for (int i = 0; i <= data_len; i++) {
        p_data[i] = (unsigned char) ((hex2int(data[3 * i + 1]) << 4) + hex2int(data[3 * i + 2]));
    }
}

int HTTP::remove_f(unsigned char *data, uf4 *dl) {
    if (flag) {
        return 1;
    } else {
        const char *start = NULL;
        const char *end = NULL;
        uf4 data_1_len = 0;
        int i;
        for (i = 2; i < 14; i += 2) {
            start = strstr((const char *) data, _request_path_[i]);
            if (i >= 8) {
                end = strstr((const char *) data, _request_path_[i + 1]);
            } else {
                end = strstr((const char *) data, http);
            }
            if (start == NULL || end == NULL) {
                continue;
            } else {
                break;
            }
        }
        if (start == NULL and end == NULL) {
            i = 0;
            start = strstr((const char *) data, get_post);
            end = strstr((const char *) data, http);
        }
        if (start == NULL || end == NULL) {
            return 0;
        }
        if (i == 0) {
            start += strlen(get_post);
        }
        data_1_len = end - start - strlen(_request_path_[i]);
        if (data_1_len % 3 != 0) {
            return 0;
        }
        const char *dst_rnrn = strstr((const char *) data, rnrn);
        if (dst_rnrn == NULL) {
            return 0;
        }
        uf4 data_2_len = *dl - (dst_rnrn - (const char *) data) - strlen(rnrn);
        uf *tmp_data = new uf[1500];
        uf4 tmp_data_len = data_1_len / 3;
        hex2char(start + strlen(_request_path_[i]), tmp_data, tmp_data_len);
        memcpy(tmp_data + tmp_data_len, dst_rnrn + strlen(rnrn), data_2_len);
        tmp_data_len += data_2_len;
        memcpy(data, tmp_data, tmp_data_len);
        *dl = tmp_data_len;
        delete tmp_data;
        flag = 1;
        return 1;
    }
}

int HTTP::remove_d(unsigned char *data, uf4 *dl) {
    if (flag) {
        return 1;
    } else {
        unsigned char * dst = strstr_f((char*)data, (char*)rnrn, *dl, 4);
        if(dst == NULL){
            cout << "rnrn do not found!" << endl;
            return 0;
        }
        memcpy(data,dst+4,*dl + data - dst -4);
        *dl = *dl + data - dst -4;
        flag = 1;
        return 1;
    }
}

struct tls_status {
    uf4 pkt_read_len;
    uf4 tls_pkt_unread_len;
};

class TLS {
public:
    struct tls_status TS;

    TLS();

    int remove_f(unsigned char *data, uf4 *dl);
};

TLS::TLS() {
    TS = {0};
}

int TLS::remove_f(unsigned char *data, uf4 *dl) {
    char tls[3] = {0x17, 0x03, 0x03};
    uf *tmp_data = new uf[65535];
    uf4 tmp_data_len = 0;
    while (TS.pkt_read_len < *dl) {
        if (TS.tls_pkt_unread_len != 0) {
            if (TS.tls_pkt_unread_len <= *dl) {
                memcpy((void *) tmp_data, data, TS.tls_pkt_unread_len);
                TS.pkt_read_len += TS.tls_pkt_unread_len;
                tmp_data_len = TS.tls_pkt_unread_len;
                TS.tls_pkt_unread_len = 0;
            } else {
                memcpy((void *) tmp_data, data, *dl);
                TS.pkt_read_len += *dl;
                TS.tls_pkt_unread_len -= *dl;
                tmp_data_len = *dl;
            }
            continue;
        }
        unsigned char *st = strstr_f((char *) (data + TS.pkt_read_len), tls, *dl - TS.pkt_read_len, sizeof(tls));
        if (st == NULL) {
            return 0;
        }

        //bug
        uf4 pkt_len = (*(st + 3) << 8) + *(st + 4);
        TS.pkt_read_len = st - (unsigned char *) data + 5;
        //bug

        if ((TS.pkt_read_len + pkt_len) < *dl) {
            memcpy(tmp_data + tmp_data_len, data + TS.pkt_read_len, pkt_len);
            TS.pkt_read_len += pkt_len;
            tmp_data_len += pkt_len;
        } else {
            memcpy(tmp_data + tmp_data_len, data + TS.pkt_read_len, (*dl - TS.pkt_read_len));
            TS.tls_pkt_unread_len = pkt_len - (*dl - TS.pkt_read_len);
            tmp_data_len += (*dl - TS.pkt_read_len);
            TS.pkt_read_len = *dl;
        }
    }

    memcpy(data, tmp_data, tmp_data_len);
    *dl = tmp_data_len;
    TS.pkt_read_len = 0;
    return 1;
}

template<class T>
T Crate() {
    T t;
    return t;
}

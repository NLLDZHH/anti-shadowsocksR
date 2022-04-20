#include "heard.h"

template<class A,class B,class C>
class one_way_flow{
public:
    uf4 op_dl;      //the length of one packet
    uf* data;       //the data of now
    uf4 dl;         //the length of now data
    A a();
    B b();
    C c();
    one_way_flow();
    ~one_way_flow();
    int remove_f();
};

one_way_flow<A,B,C>::one_way_flow() {
    data = new uf[65535];
}

one_way_flow<A,B,C>::~one_way_flow() {
    delete data;
}

int one_way_flow<A,B,C>::remove_f() {
    return 0;
}
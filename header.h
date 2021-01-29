//#include <stdint.h>
#include <string.h>
#include <map>

using namespace std;

struct MAC{
    uint8_t MAC_a[6];
    bool operator <(const MAC &var) const
    {
        return memcmp(MAC_a, var.MAC_a, sizeof(MAC)) < 0;
    }
};


struct ETHER{
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
};

struct IP{
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct VALUES{
    unsigned int Tx_packets;
    unsigned int Tx_bytes;
    unsigned int Rx_packets;
    unsigned int Rx_bytes;

};


void ntoa(uint32_t ip, char * dst){
    sprintf(dst, "%d.%d.%d.%d", ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}


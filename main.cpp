//#include <iostream>
#include <stdio.h>
//#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <map>
//#include <arpa/inet.h>
//#include <netinet/in.h>
//#include <net/ethernet.h>
#include <netinet/ip.h>
#include "header.h"

using namespace std;

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_offline("/home/ubuntu/STL/test.pcap", errbuf);

    if (handle == NULL) {
            fprintf(stderr, "couldn't open file %s: %s\n", "/home/ubuntu/STL/test.pcap", errbuf);
            return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    map<uint32_t,VALUES> ip_;
    map<MAC,VALUES> mac_;

    while(handle != NULL){

        int res = pcap_next_ex(handle, &header, &data);
        if (res == 0) continue;
        if (res == -2) break;



        struct ETHER * mac_key = (struct ETHER *)data;
        struct IP * ip_key = (struct IP *)(data+14);   //ether header => 14


        if(ntohs(mac_key->ether_type) == 0x0800){


            //process add mac map

            MAC mac_a_r,mac_a_t;

            memcpy(mac_a_r.MAC_a,mac_key->dst_MAC,sizeof(mac_a_r));
            memcpy(mac_a_t.MAC_a,mac_key->src_MAC,sizeof(mac_a_t));





            if (mac_.find(mac_a_r) == mac_.end()){
                VALUES val;

                val.Tx_bytes=0;
                val.Rx_bytes=header->len;
                val.Tx_packets=0;
                val.Rx_packets=1;

                mac_.insert(pair<MAC,VALUES>((mac_a_r),val));

            }
            else{
                mac_[mac_a_r].Rx_packets  += 1;
                mac_[mac_a_r].Rx_bytes += header->len;
            }
            if (mac_.find(mac_a_t) == mac_.end()){
                VALUES val;

                val.Tx_bytes=header->len;
                val.Rx_bytes=0;
                val.Tx_packets=1;
                val.Rx_packets=0;

                mac_.insert(pair<MAC,VALUES>((mac_a_t),val));

            }
            else{
                mac_[mac_a_t].Tx_packets  += 1;
                mac_[mac_a_t].Tx_bytes += header->len;
            }
        
        

            //procss add ip map
            if (ip_.find(ip_key->dst_ip) == ip_.end()){
                VALUES val;

                val.Tx_bytes=0;
                val.Rx_bytes=header->len;
                val.Tx_packets=0;
                val.Rx_packets=1;

                ip_.insert(pair<uint32_t,VALUES>((ip_key->dst_ip),val));
            }
            else{
                ip_[ip_key->dst_ip].Rx_packets  += 1;
                ip_[ip_key->dst_ip].Rx_bytes += header->len;
            }

            if (ip_.find(ip_key->src_ip) == ip_.end()){
                VALUES val;

                val.Tx_bytes=header->len;
                val.Rx_bytes=0;
                val.Tx_packets=1;
                val.Rx_packets=0;

                ip_.insert(pair<uint32_t,VALUES>((ip_key->src_ip),val));
            }
            else{
                ip_[ip_key->src_ip].Tx_packets  += 1;
                ip_[ip_key->src_ip].Tx_bytes += header->len;
            }

        }
    }


    pcap_close(handle);






    //print ip endpoint
    printf("<IPv4 Endpoints>\n");
    printf("------------------------------------------------------------------------------------\n");
    printf("|     Address      |   Tx Packets  |    Tx Bytes   |   Rx Packets  |    Rx Bytes   |\n");
    printf("------------------------------------------------------------------------------------\n");
    map<uint32_t, VALUES>::iterator iter;
    for(iter = ip_.begin(); iter != ip_.end(); ++iter){
        char addr[18];
        ntoa(iter->first, addr);

        printf("|%18s|%15d|%15d|%15d|%15d|\n", addr,
         iter->second.Tx_packets,iter->second.Tx_bytes, iter->second.Rx_packets, iter->second.Rx_bytes);
        printf("------------------------------------------------------------------------------------\n");
    }

    printf("\n\n");



    //print mac endpoint
    printf("<Ethernet Endpoints>\n");
    printf("------------------------------------------------------------------------------------\n");
    printf("|     Address      |   Tx Packets  |    Tx Bytes   |   Rx Packets  |    Rx Bytes   |\n");
    printf("------------------------------------------------------------------------------------\n");
    map<MAC, VALUES>::iterator iter_;
    for(iter_ = mac_.begin(); iter_ != mac_.end(); ++iter_){



        //because array
        printf("|%02X:%02X:%02X:%02X:%02X:%02X |%15d|%15d|%15d|%15d|\n",
               iter_->first.MAC_a[0],
               iter_->first.MAC_a[1],
               iter_->first.MAC_a[2],
               iter_->first.MAC_a[3],
               iter_->first.MAC_a[4],
               iter_->first.MAC_a[5],
         iter_->second.Tx_packets,iter_->second.Tx_bytes, iter_->second.Rx_packets, iter_->second.Rx_bytes);
        printf("------------------------------------------------------------------------------------\n");
    }




}


#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>

using namespace std;

// Hàm xử lý mỗi gói tin bắt được
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    cout << "\n========== GOI TIN MOI ==========" << endl;
    cout << "Thoi gian: " << ctime((const time_t*)&pkthdr->ts.tv_sec);
    cout << "Kich thuoc goi tin: " << pkthdr->len << " bytes" << endl;
    
    // Phân tích Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    cout << "MAC nguon: ";
    for(int i = 0; i < 6; i++) {
        printf("%02x", eth_header->ether_shost[i]);
        if(i < 5) cout << ":";
    }
    cout << endl;
    
    cout << "MAC dich: ";
    for(int i = 0; i < 6; i++) {
        printf("%02x", eth_header->ether_dhost[i]);
        if(i < 5) cout << ":";
    }
    cout << endl;
    
    // Kiểm tra nếu là gói IP
    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        
        cout << "Giao thuc: IP" << endl;
        cout << "IP nguon: " << inet_ntoa(ip_header->ip_src) << endl;
        cout << "IP dich: " << inet_ntoa(ip_header->ip_dst) << endl;
        cout << "TTL: " << (int)ip_header->ip_ttl << endl;
        
        // Kiểm tra giao thức tầng Transport
        if(ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Giao thuc tang Transport: TCP" << endl;
            cout << "Port nguon: " << ntohs(tcp_header->th_sport) << endl;
            cout << "Port dich: " << ntohs(tcp_header->th_dport) << endl;
            cout << "Sequence Number: " << ntohl(tcp_header->th_seq) << endl;
            cout << "ACK Number: " << ntohl(tcp_header->th_ack) << endl;
        }
        else if(ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            cout << "Giao thuc tang Transport: UDP" << endl;
            cout << "Port nguon: " << ntohs(udp_header->uh_sport) << endl;
            cout << "Port dich: " << ntohs(udp_header->uh_dport) << endl;
        }
        else if(ip_header->ip_p == IPPROTO_ICMP) {
            cout << "Giao thuc tang Transport: ICMP" << endl;
        }
        else {
            cout << "Giao thuc tang Transport: Khac (" << (int)ip_header->ip_p << ")" << endl;
        }
    }
    
    cout << "================================" << endl;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device;
    
    cout << "===== CHUONG TRINH BAT GOI TIN =====" << endl;
    
    // Tìm thiết bị mạng mặc định
    if(argc > 1) {
        device = argv[1];
    } else {
        device = pcap_lookupdev(errbuf);
        if(device == NULL) {
            cerr << "Khong tim thay thiet bi mang: " << errbuf << endl;
            return 1;
        }
    }
    
    cout << "Thiet bi mang: " << device << endl;
    
    // Mở thiết bị để bắt gói tin
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        cerr << "Khong the mo thiet bi " << device << ": " << errbuf << endl;
        return 1;
    }
    
    cout << "Bat dau bat goi tin... (Nhan Ctrl+C de dung)" << endl;
    cout << "=====================================" << endl;
    
    // Bắt đầu bắt gói tin (vòng lặp vô hạn)
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Đóng handle
    pcap_close(handle);
    
    return 0;
}

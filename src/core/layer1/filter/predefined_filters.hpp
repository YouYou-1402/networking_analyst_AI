// src/core/layer1/filter/predefined_filters.hpp

#ifndef NETWORK_SECURITY_PREDEFINED_FILTERS_HPP
#define NETWORK_SECURITY_PREDEFINED_FILTERS_HPP

#include <string>
#include <unordered_map>
#include <vector>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            /**
             * @brief Predefined filters (Wireshark-like macros)
             */
            class PredefinedFilters
            {
            public:
                /**
                 * @brief Get all predefined filter names
                 */
                static std::vector<std::string> getFilterNames();

                /**
                 * @brief Get filter by name
                 */
                static std::string getFilter(const std::string& name);

                /**
                 * @brief Check if filter name exists
                 */
                static bool exists(const std::string& name);

                // ==================== Protocol Filters ====================
                static std::string tcp() { return "tcp"; }
                static std::string udp() { return "udp"; }
                static std::string icmp() { return "icmp"; }
                static std::string arp() { return "arp"; }
                static std::string ip() { return "ip"; }
                static std::string ipv6() { return "ipv6"; }

                // ==================== Application Protocols ====================
                static std::string http() { return "http"; }
                static std::string https() { return "https"; }
                static std::string dns() { return "dns"; }
                static std::string ssh() { return "ssh"; }
                static std::string ftp() { return "ftp"; }
                static std::string smtp() { return "smtp"; }
                static std::string pop() { return "pop"; }
                static std::string imap() { return "imap"; }
                static std::string telnet() { return "telnet"; }
                static std::string dhcp() { return "dhcp"; }
                static std::string ntp() { return "ntp"; }
                static std::string snmp() { return "snmp"; }

                // ==================== Port Filters ====================
                static std::string httpTraffic() { return "tcp.port == 80 or tcp.port == 8080"; }
                static std::string httpsTraffic() { return "tcp.port == 443 or tcp.port == 8443"; }
                static std::string dnsTraffic() { return "udp.port == 53 or tcp.port == 53"; }
                static std::string sshTraffic() { return "tcp.port == 22"; }
                static std::string ftpTraffic() { return "tcp.port == 21 or tcp.port == 20"; }
                static std::string smtpTraffic() { return "tcp.port == 25 or tcp.port == 587"; }

                // ==================== TCP Flags ====================
                static std::string tcpSyn() { return "tcp.flags.syn == 1 and tcp.flags.ack == 0"; }
                static std::string tcpSynAck() { return "tcp.flags.syn == 1 and tcp.flags.ack == 1"; }
                static std::string tcpAck() { return "tcp.flags.ack == 1"; }
                static std::string tcpFin() { return "tcp.flags.fin == 1"; }
                static std::string tcpRst() { return "tcp.flags.reset == 1"; }
                static std::string tcpPsh() { return "tcp.flags.push == 1"; }
                static std::string tcpUrg() { return "tcp.flags.urg == 1"; }

                // ==================== TCP Issues ====================
                static std::string tcpRetransmission() { return "tcp.analysis.retransmission"; }
                static std::string tcpFastRetransmission() { return "tcp.analysis.fast_retransmission"; }
                static std::string tcpDupAck() { return "tcp.analysis.duplicate_ack"; }
                static std::string tcpZeroWindow() { return "tcp.analysis.zero_window"; }
                static std::string tcpLostSegment() { return "tcp.analysis.lost_segment"; }
                static std::string tcpOutOfOrder() { return "tcp.analysis.out_of_order"; }
                static std::string tcpKeepAlive() { return "tcp.analysis.keep_alive"; }
                static std::string tcpIssues() { 
                    return "tcp.analysis.retransmission or tcp.analysis.duplicate_ack or "
                           "tcp.analysis.zero_window or tcp.analysis.lost_segment"; 
                }

                // ==================== IP Filters ====================
                static std::string broadcast() { return "eth.dst == ff:ff:ff:ff:ff:ff"; }
                static std::string multicast() { return "ip.dst >= 224.0.0.0 and ip.dst <= 239.255.255.255"; }
                static std::string ipv6Multicast() { return "ipv6.dst[0] == 0xff"; }
                static std::string privateIP() {
                    return "(ip.addr >= 10.0.0.0 and ip.addr <= 10.255.255.255) or "
                           "(ip.addr >= 172.16.0.0 and ip.addr <= 172.31.255.255) or "
                           "(ip.addr >= 192.168.0.0 and ip.addr <= 192.168.255.255)";
                }

                // ==================== ARP ====================
                static std::string arpRequest() { return "arp.opcode == 1"; }
                static std::string arpReply() { return "arp.opcode == 2"; }
                static std::string gratuitousArp() { return "arp.isgratuitous"; }
                static std::string arpProbe() { return "arp.isprobe"; }
                static std::string arpDuplicate() { return "arp.duplicate-address-detected"; }

                // ==================== ICMP ====================
                static std::string icmpEchoRequest() { return "icmp.type == 8"; }
                static std::string icmpEchoReply() { return "icmp.type == 0"; }
                static std::string icmpUnreachable() { return "icmp.type == 3"; }
                static std::string icmpTimeExceeded() { return "icmp.type == 11"; }
                static std::string icmpRedirect() { return "icmp.type == 5"; }

                // ==================== Combinations ====================
                static std::string webTraffic() { return "http or https"; }
                static std::string mailTraffic() { return "smtp or pop or imap"; }
                static std::string databaseTraffic() { 
                    return "tcp.port == 3306 or tcp.port == 5432 or tcp.port == 1433 or "
                           "tcp.port == 27017 or tcp.port == 6379"; 
                }
                static std::string encryptedTraffic() { return "https or ssh"; }

                // ==================== Security ====================
                static std::string portScan() { 
                    return "tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024"; 
                }
                static std::string synFlood() { 
                    return "tcp.flags.syn == 1 and tcp.flags.ack == 0"; 
                }
                static std::string rstAttack() { return "tcp.flags.reset == 1"; }
                static std::string largePackets() { return "frame.len > 1500"; }
                static std::string smallPackets() { return "frame.len < 64"; }

            private:
                static std::unordered_map<std::string, std::string> filter_map_;
                static void initializeFilterMap();
            };

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_SECURITY_PREDEFINED_FILTERS_HPP

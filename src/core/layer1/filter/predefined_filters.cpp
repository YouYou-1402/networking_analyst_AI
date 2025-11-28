// src/core/layer1/filter/predefined_filters.cpp

#include "predefined_filters.hpp"
#include <algorithm>

namespace NetworkSecurity
{
    namespace Layer1
    {
        namespace Filter
        {
            // Static member initialization
            std::unordered_map<std::string, std::string> PredefinedFilters::filter_map_;

            void PredefinedFilters::initializeFilterMap()
            {
                if (!filter_map_.empty())
                    return;

                // ==================== Protocol Filters ====================
                filter_map_["tcp"] = tcp();
                filter_map_["udp"] = udp();
                filter_map_["icmp"] = icmp();
                filter_map_["arp"] = arp();
                filter_map_["ip"] = ip();
                filter_map_["ipv6"] = ipv6();

                // ==================== Application Protocols ====================
                filter_map_["http"] = http();
                filter_map_["https"] = https();
                filter_map_["dns"] = dns();
                filter_map_["ssh"] = ssh();
                filter_map_["ftp"] = ftp();
                filter_map_["smtp"] = smtp();
                filter_map_["pop"] = pop();
                filter_map_["imap"] = imap();
                filter_map_["telnet"] = telnet();
                filter_map_["dhcp"] = dhcp();
                filter_map_["ntp"] = ntp();
                filter_map_["snmp"] = snmp();

                // ==================== Port Filters ====================
                filter_map_["http.traffic"] = httpTraffic();
                filter_map_["https.traffic"] = httpsTraffic();
                filter_map_["dns.traffic"] = dnsTraffic();
                filter_map_["ssh.traffic"] = sshTraffic();
                filter_map_["ftp.traffic"] = ftpTraffic();
                filter_map_["smtp.traffic"] = smtpTraffic();

                // ==================== TCP Flags ====================
                filter_map_["tcp.syn"] = tcpSyn();
                filter_map_["tcp.synack"] = tcpSynAck();
                filter_map_["tcp.ack"] = tcpAck();
                filter_map_["tcp.fin"] = tcpFin();
                filter_map_["tcp.rst"] = tcpRst();
                filter_map_["tcp.psh"] = tcpPsh();
                filter_map_["tcp.urg"] = tcpUrg();

                // ==================== TCP Issues ====================
                filter_map_["tcp.retransmission"] = tcpRetransmission();
                filter_map_["tcp.fast_retransmission"] = tcpFastRetransmission();
                filter_map_["tcp.dup_ack"] = tcpDupAck();
                filter_map_["tcp.zero_window"] = tcpZeroWindow();
                filter_map_["tcp.lost_segment"] = tcpLostSegment();
                filter_map_["tcp.out_of_order"] = tcpOutOfOrder();
                filter_map_["tcp.keep_alive"] = tcpKeepAlive();
                filter_map_["tcp.issues"] = tcpIssues();

                // ==================== IP Filters ====================
                filter_map_["broadcast"] = broadcast();
                filter_map_["multicast"] = multicast();
                filter_map_["ipv6.multicast"] = ipv6Multicast();
                filter_map_["private.ip"] = privateIP();

                // ==================== ARP ====================
                filter_map_["arp.request"] = arpRequest();
                filter_map_["arp.reply"] = arpReply();
                filter_map_["arp.gratuitous"] = gratuitousArp();
                filter_map_["arp.probe"] = arpProbe();
                filter_map_["arp.duplicate"] = arpDuplicate();

                // ==================== ICMP ====================
                filter_map_["icmp.echo_request"] = icmpEchoRequest();
                filter_map_["icmp.echo_reply"] = icmpEchoReply();
                filter_map_["icmp.unreachable"] = icmpUnreachable();
                filter_map_["icmp.time_exceeded"] = icmpTimeExceeded();
                filter_map_["icmp.redirect"] = icmpRedirect();

                // ==================== Combinations ====================
                filter_map_["web.traffic"] = webTraffic();
                filter_map_["mail.traffic"] = mailTraffic();
                filter_map_["database.traffic"] = databaseTraffic();
                filter_map_["encrypted.traffic"] = encryptedTraffic();

                // ==================== Security ====================
                filter_map_["port.scan"] = portScan();
                filter_map_["syn.flood"] = synFlood();
                filter_map_["rst.attack"] = rstAttack();
                filter_map_["large.packets"] = largePackets();
                filter_map_["small.packets"] = smallPackets();
            }

            std::vector<std::string> PredefinedFilters::getFilterNames()
            {
                initializeFilterMap();
                
                std::vector<std::string> names;
                names.reserve(filter_map_.size());
                
                for (const auto& pair : filter_map_)
                {
                    names.push_back(pair.first);
                }
                
                // Sort alphabetically for better usability
                std::sort(names.begin(), names.end());
                
                return names;
            }

            std::string PredefinedFilters::getFilter(const std::string& name)
            {
                initializeFilterMap();
                
                auto it = filter_map_.find(name);
                if (it != filter_map_.end())
                {
                    return it->second;
                }
                
                return "";
            }

            bool PredefinedFilters::exists(const std::string& name)
            {
                initializeFilterMap();
                return filter_map_.find(name) != filter_map_.end();
            }

        } // namespace Filter
    } // namespace Layer1
} // namespace NetworkSecurity

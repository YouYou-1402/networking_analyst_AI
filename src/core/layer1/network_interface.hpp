// src/core/layer1/network_interface.hpp

#ifndef NETWORK_INTERFACE_HPP
#define NETWORK_INTERFACE_HPP

#include <string>
#include <vector>

namespace NetworkSecurity
{
    namespace Layer1
    {
        /**
         * @brief Network interface information
         */
        struct NetworkInterface
        {
            std::string name;                    // Interface name (e.g., "eth0", "wlan0")
            std::string description;             // Human-readable description
            std::vector<std::string> addresses;  // IP addresses
            bool is_up;                          // Interface is up
            bool is_loopback;                    // Is loopback interface
            bool is_wireless;                    // Is wireless interface
            int mtu;                             // Maximum transmission unit
            uint64_t speed;                      // Link speed in bps (0 if unknown)
            
            // Statistics (optional)
            uint64_t packets_sent;
            uint64_t packets_received;
            uint64_t bytes_sent;
            uint64_t bytes_received;
            uint64_t errors;
            uint64_t dropped;

            NetworkInterface()
                : is_up(false),
                  is_loopback(false),
                  is_wireless(false),
                  mtu(0),
                  speed(0),
                  packets_sent(0),
                  packets_received(0),
                  bytes_sent(0),
                  bytes_received(0),
                  errors(0),
                  dropped(0)
            {}
        };

    } // namespace Layer1
} // namespace NetworkSecurity

#endif // NETWORK_INTERFACE_HPP

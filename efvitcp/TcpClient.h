/*
MIT License

Copyright (c) 2021 Meng Rao <raomeng1@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once

#include "Core.h"
#include "TcpConn.h"

namespace efvitcp {

template<typename Conf>
class TcpClient
{
public:
  // A configuration structure for the client, inheriting from the base configuration (Conf).
  // Defines the maximum number of connections for this client (1 in this case).
  struct CliConf : public Conf
  {
    static const int MaxConnCnt = 1;
  };

  // Type alias for a TcpConn instance with the specific client configuration.
  using Conn = TcpConn<CliConf>;

  // Destructor ensures resources are cleaned up properly when the TcpClient is destroyed.
  ~TcpClient() { close(); }

  // Initializes the TCP client, setting up the core and connection instance.
  const char* init(const char* interface) {
    // Initialize the core using the specified network interface.
    const char* err = core.init(interface);
    if (err) return err;  // If initialization fails, return the error.
    
    // Initialize the connection object.
    conn.init(&core, (uint8_t*)core.getSendBuf(0), 0);
    
    return nullptr;  // No error occurred, return nullptr.
  }

  // Closes the TCP client connection and removes any filters.
  void close() {
    conn.close();  // Close the connection.
    core.delFilter();  // Remove the filter from the core.
  }

  // Getter function for accessing the connection object.
  Conn& getConn() { return conn; }

  // Establishes a TCP connection to the specified server with the provided IP and port.
  const char* connect(const char* server_ip, uint16_t server_port, uint16_t local_port = 0) {
    // Check if a connection already exists (only one is allowed).
    if (core.conn_cnt) return "Connection already exists";
    
    // Convert the server IP address to a uint32_t format (network byte order).
    uint32_t remote_ip;
    if (!inet_pton(AF_INET, server_ip, &remote_ip)) return "Invalid server ip";

    // Get the MAC address of the destination server.
    uint8_t dst_mac[6];
    const char* err;
    if ((err = getDestMac(server_ip, dst_mac))) return err;  // If MAC address retrieval fails, return the error.

    // Convert ports to network byte order (big-endian).
    server_port = htons(server_port);
    local_port = htons(local_port);

    // Set up the client-side filter to match the provided IP and port.
    if ((err = core.setClientFilter(local_port, remote_ip, server_port))) return err;

    // Reset the connection object with the local port, destination MAC, remote IP, and server port.
    conn.reset(local_port, dst_mac, remote_ip, server_port);

    // Send the initial SYN packet to initiate the connection.
    conn.sendSyn();

    // Generate a unique hash key for the connection based on the remote IP and port.
    uint64_t key = connHashKey(remote_ip, server_port);
    
    // Increment the connection count and add the new connection entry to the core.
    core.conn_cnt++;
    core.addConnEntry(core.findConnEntry(key), key, 0);

    return nullptr;  // Connection successfully initiated.
  }

  // Polls the connection for events and handles incoming data.
  // The EventHandler is used to handle events such as packet reception or connection setup.
  template<typename EventHandler>
  void poll(EventHandler& handler, int64_t ns = 0) {
    // Poll for timed events (e.g., timeouts or retransmissions).
    core.pollTime([&](TimerNode* node) { return conn.onTimer(handler, node); }, ns);

    // Poll for network events, processing incoming packets.
    core.pollNet([&](uint64_t key, ConnHashEntry* entry, EtherHeader* eth_hdr) {
      IpHeader* ip_hdr = (IpHeader*)(eth_hdr + 1);  // Extract the IP header from the Ethernet frame.
      TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);  // Extract the TCP header from the IP header.

      // Check if the connection key matches the expected key, otherwise, send a reset response.
      if (entry->key != key) {
        core.rspRst(eth_hdr);
        return;
      }

      // If the connection is not yet established (SYN sent), check if the SYN-ACK handshake is successful.
      if (!conn.established) { // Syn Sent
        bool ack_ok = tcp_hdr->ack && tcp_hdr->ack_num == conn.getSendBuf(conn.send_next)->tcp_hdr.seq_num;
        if (!ack_ok) {
          core.rspRst(eth_hdr);  // If the ACK is invalid, reset the connection.
          return;
        }

        // If the server sent a RST (reset) packet, notify the handler and close the connection.
        if (tcp_hdr->rst) {
          handler.onConnectionRefused();
          conn.onClose();
          return;
        }

        // If the server sent a SYN-ACK, the connection is established.
        if (!tcp_hdr->syn) return;
        conn.onSyn(ip_hdr);
        conn.onEstablished(handler, ip_hdr);
      }

      // Handle the incoming TCP packet.
      conn.onPack(handler, ip_hdr);
    });
  }

private:
  // Helper function to retrieve the MAC address of the gateway for a given destination IP.
  const char* getDestMac(const char* dest_ip, uint8_t* dest_mac) {
    // Command to get the route to the destination IP.
#define IPRouteGetCmd "/usr/sbin/ip route get"
#define NetARPFile "/proc/net/arp"

    char buf[1024];  // Buffer for reading command output.
    char gw_ip[64];  // Gateway IP address.
    char ip[64];     // IP address from ARP cache.
    bool found = false;
    
    // Execute the system command to get the route to the destination IP.
    sprintf(buf, IPRouteGetCmd " %s", dest_ip);
    FILE* pipe = popen(buf, "r");
    if (!pipe) return IPRouteGetCmd " failed";

    // Read the output of the route command and extract the gateway IP.
    while (fgets(buf, sizeof(buf), pipe)) {
      const char* str = buf;
      if (char* pos = strstr(buf, " via ")) {
        str = pos + 5;
      }
      if (sscanf(str, "%s dev %*s src %*s", gw_ip) == 1) {
        found = true;
        break;
      }
    }
    pclose(pipe);
    if (!found) return "Can't find gw by " IPRouteGetCmd;

    // Open the ARP cache file to find the MAC address for the gateway IP.
    FILE* arp_file = fopen(NetARPFile, "r");
    if (!arp_file) return "Can't open " NetARPFile;
    if (!fgets(buf, sizeof(buf), arp_file)) {
      fclose(arp_file);
      return "Invalid file " NetARPFile;
    }

    // Search the ARP cache for the gateway IP's MAC address.
    found = false;
    char hw[64];  // Hardware address (MAC address).
    while (2 == fscanf(arp_file, "%63s %*s %*s %63s %*s %*s", ip, hw)) {
      if (!strcmp(ip, gw_ip)) {
        found = true;
        break;
      }
    }
    fclose(arp_file);

    if (!found) return "Can't find dest ip from arp cache, please ping dest ip first";

    // Verify if the MAC address is valid.
    bool valid_mac = strlen(hw) == 17;  // MAC address should be in the format "XX:XX:XX:XX:XX:XX".
    auto hexchartoi = [&valid_mac](char c) -> uint8_t {
      if (c >= '0' && c <= '9') return c - '0';
      else if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      else {
        valid_mac = false;
        return 0;
      }
    };

    // If the MAC address is valid, convert the MAC address string to bytes.
    if (valid_mac) {
      for (int i = 0; i < 6; ++i) {
        dest_mac[i] = hexchartoi(hw[3 * i]) * 16 + hexchartoi(hw[3 * i + 1]);
      }
    }

    // Return error if the MAC address is invalid.
    if (!valid_mac) return "Invalid dest mac addr";
    return nullptr;  // Successfully retrieved the MAC address.
  }

  Core<CliConf> core;  // Core networking functionality for the client.
  Conn conn;  // The connection object for the TCP client.
};

} // namespace efvitcp

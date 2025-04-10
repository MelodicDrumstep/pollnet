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
class TcpServer
{
public:
  // Define the connection type as a TcpConn object using the configuration template Conf.
  using Conn = TcpConn<Conf>;

  // Destructor: Close all connections and clean up resources.
  ~TcpServer() { close(); }

  // Initializes the server by setting up the core and creating multiple connections.
  const char* init(const char* interface) {
    // Initialize the core functionality with the given network interface.
    const char* err = core.init(interface);
    if (err) return err;  // If initialization fails, return the error.

    // Initialize each connection in the array with the core and a send buffer.
    for (uint32_t i = 0; i < Conf::MaxConnCnt; i++) {
      conns[i].init(&core, (uint8_t*)core.getSendBuf(i * Conf::ConnSendBufCnt), i);
    }
    return nullptr;  // No error occurred, return nullptr.
  }

  // Close all connections and remove any filters from the core.
  void close() {
    // Loop through all active connections and close them.
    for (auto& conn : conns) {
      conn.close();
    }
    // Remove the filter from the core.
    core.delFilter();
  }

  // Returns the current number of connections.
  uint32_t getConnCnt() { return core.conn_cnt; }

  // Iterates over all established connections and invokes the given handler for each one.
  template<typename Handler>
  void foreachConn(Handler handler) {
    for (auto& conn : conns) {
      if (conn.isEstablished()) handler(conn);  // Only handle established connections.
    }
  }

  // Sets the server to listen on the given port.
  const char* listen(uint16_t server_port) {
    // Convert the server port to network byte order (big-endian).
    server_port_be = htons(server_port);
    
    // Set the server filter to listen on the specified port.
    const char* err;
    if ((err = core.setServerFilter(server_port_be))) return err;  // If setting filter fails, return error.

    return nullptr;  // Successfully set the server filter.
  }

  // Polls for network events and processes incoming data.
  template<typename EventHandler>
  void poll(EventHandler& handler, int64_t ns = 0) {
    // Poll for time-based events (such as timers).
    core.pollTime(
      [&](TimerNode* node) {
        // For each timed event, handle it using the corresponding connection.
        Conn& conn = conns[node->conn_id];
        return conn.onTimer(handler, node);
      },
      ns);

    // Poll for network events (such as incoming packets).
    core.pollNet([&](uint64_t key, ConnHashEntry* entry, EtherHeader* eth_hdr) {
      // Extract the IP and TCP headers from the Ethernet frame.
      IpHeader* ip_hdr = (IpHeader*)(eth_hdr + 1);
      TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);

      // Check if the connection key in the entry matches the given key.
      if (entry->key != key) {
        // If the keys do not match and the packet is a reset (RST), discard it.
        if (tcp_hdr->rst) return;

        // Otherwise, check if the connection can be established or if new connections are allowed.
        if (tcp_hdr->ack || !tcp_hdr->syn || (core.conn_cnt == Conf::MaxConnCnt) ||
            !handler.allowNewConnection(ip_hdr->src_ip, tcp_hdr->src_port)) {
          // If not allowed, send a reset (RST) packet and return.
          core.rspRst(eth_hdr);
          return;
        }

        // Allocate a new connection ID and increment the connection counter.
        uint32_t conn_id = core.conns[core.conn_cnt++];
        core.addConnEntry(entry, key, conn_id);

        // Initialize the new connection with the destination IP and MAC addresses.
        Conn& conn = conns[conn_id];
        conn.reset(server_port_be, eth_hdr->src_mac, ip_hdr->src_ip, tcp_hdr->src_port);

        // Handle the SYN packet (start of connection establishment).
        conn.onSyn(ip_hdr);
        conn.sendSyn();  // Send the initial SYN to the client to start the handshake.
        return;
      }

      // If the connection key matches, find the corresponding connection entry.
      Conn& conn = conns[entry->conn_id];

      // If the connection is not yet established (SYN received):
      if (!conn.established) {  // Syn Received
        // Handle the case where the SYN packet is received without an ACK.
        if (tcp_hdr->syn && !tcp_hdr->ack) {
          conn.resendUna(false);  // Resend unacknowledged data if needed.
          return;
        }

        // If a reset (RST) packet is received, check if the sequence number matches and close the connection.
        if (tcp_hdr->rst && ntohl(tcp_hdr->seq_num) == conn.recv_buf_seq + conn.segs[0].second) {
          conn.onClose();  // Close the connection if reset is valid.
          return;
        }

        // If the packet is not an ACK, we ignore it.
        if (!tcp_hdr->ack) return;

        // If the ACK number doesn't match the expected value, respond with a reset.
        if (tcp_hdr->ack_num != conn.getSendBuf(conn.send_next)->tcp_hdr.seq_num) {
          core.rspRst(eth_hdr);  // Send a reset (RST) packet.
          return;
        }

        // The connection is now established, invoke the handler and process the packet.
        conn.onEstablished(handler, ip_hdr);
      }

      // After the connection is established, handle the incoming data packet.
      conn.onPack(handler, ip_hdr);
    });
  }

private:
  Core<Conf> core;  // Core network functionality that handles lower-level operations.
  uint16_t server_port_be;  // The server port in network byte order (big-endian).
  Conn conns[Conf::MaxConnCnt];  // Array of connections, with a maximum count defined by Conf::MaxConnCnt.
};

} // namespace efvitcp
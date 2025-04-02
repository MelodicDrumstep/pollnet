/*
MIT License

Copyright (c) 2019 Meng Rao <raomeng1@gmail.com>

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
#include <arpa/inet.h>

/**
 * TCP Stream Reassembler - Reconstructs ordered TCP streams from potentially out-of-order packets
 * 
 * @tparam WaitForResend Whether to wait for retransmissions of missing packets (true) 
 *        or skip gaps in sequence numbers (false)
 * @tparam BUFSIZE Size of the receive buffer (default 1MB)
 */
template<bool WaitForResend = true, uint32_t BUFSIZE = 1 << 20>
class TcpStream
{
public:
  /**
   * Initialize packet filter criteria
   * @param src_ip Source IP address to filter ("0.0.0.0" for any)
   * @param src_port Source port to filter (0 for any)
   * @param dst_ip Destination IP address to filter ("0.0.0.0" for any)
   * @param dst_port Destination port to filter (0 for any)
   */
  void initFilter(const char* src_ip, uint16_t src_port, const char* dst_ip, uint16_t dst_port) {
    inet_pton(AF_INET, src_ip, &filter_src_ip);  // Convert IP string to binary
    inet_pton(AF_INET, dst_ip, &filter_dst_ip);
    filter_src_port = htons(src_port);  // Convert port to network byte order
    filter_dst_port = htons(dst_port);
  }

  /**
   * Check if packet matches filter criteria
   * @param data_ Pointer to packet data starting with Ethernet header
   * @param size Total packet size
   * @return true if packet matches filter, false otherwise
   */
  bool filterPacket(const void* data_, uint32_t size) {
    const uint8_t* data = (const uint8_t*)data_;
    EtherHeader& ether_header = *(EtherHeader*)data;
    IpHeader& ip_header = *(IpHeader*)(data + IPHeaderPos);
    TcpHeader& tcp_header = *(TcpHeader*)(data + TcpHeaderPos);

    // Filter criteria checks:
    if (ether_header.etherType != 0x0008) return false;  // Not IPv4
    if (ip_header.protocol != 6) return false;           // Not TCP
    if (filter_src_ip && filter_src_ip != ip_header.ipSrc) return false;
    if (filter_dst_ip && filter_dst_ip != ip_header.ipDst) return false;
    if (filter_src_port && filter_src_port != tcp_header.portSrc) return false;
    if (filter_dst_port && filter_dst_port != tcp_header.portDst) return false;
    return true;
  }

  /**
   * Process a TCP packet and reassemble the stream
   * @param data_ Pointer to packet data starting with Ethernet header
   * @param size Total packet size
   * @param handler Callback function for processed data
   * @return true if packet was processed successfully, false otherwise
   */
  template<typename Handler>
  bool handlePacket(const void* data_, uint32_t size, Handler handler) {
    const uint8_t* data = (const uint8_t*)data_;
    IpHeader& ip_header = *(IpHeader*)(data + IPHeaderPos);
    TcpHeader& tcp_header = *(TcpHeader*)(data + TcpHeaderPos);

    // Get sequence number and adjust for SYN
    uint32_t seq = ntohl(tcp_header.sequenceNumber);
    if (tcp_header.synFlag) {
      init_stream = false;  // Reset stream on SYN
      seq++;  // SYN consumes one sequence number
    }

    // Initialize stream state if this is the first packet
    if (!init_stream) {
      init_stream = true;
      buf_seq = seq;  // Starting sequence number
      n_seg = 1;      // Single empty segment
      segs[0].first = segs[0].second = 0;  // [0,0) interval
    }

    // Calculate payload position and size
    uint32_t header_len = sizeof(IpHeader) + tcp_header.dataOffset * 4;
    const uint8_t* new_data = data + IPHeaderPos + header_len;
    uint32_t new_size = ntohs(ip_header.totalLength) - header_len;

    // Calculate position in buffer
    uint32_t loc = seq - buf_seq;  // Buffer position for this sequence
    uint32_t loc_end = loc + new_size;
    
    // Adjust for packets arriving before current buffer start
    int32_t diff = loc - segs[0].second;
    if (diff < 0) {
      loc -= diff;
      new_data -= diff;
      new_size += diff;
    }

    // Validate packet data
    if ((int32_t)new_size <= 0) return false;  // Obsolete data
    if (loc_end > BUFSIZE) return false;      // Buffer full

    // Handle non-waiting mode (skip gaps)
    if (!WaitForResend && loc > segs[0].second) {
      segs[0].first = segs[0].second = loc;  // Move window forward
    }

    // Find insertion point for new segment
    uint32_t i = 0;
    while (i < n_seg && segs[i].second < loc) i++;
    
    // Find merge end point
    uint32_t j = i;
    while (j < n_seg && segs[j].first <= loc_end) j++;

    // Insert new segment or merge with existing ones
    if (i == j) {  // New segment
      if (n_seg == MAX_SEG) return false;  // Too many segments
      // Make space for new segment
      for (j = n_seg; j > i; j--) {
        segs[j] = segs[j - 1];
      }
      segs[i].first = loc;
      segs[i].second = loc_end;
      n_seg++;
    }
    else {  // Merge segments
      segs[i].first = std::min(segs[i].first, loc);
      segs[i].second = std::max(segs[j - 1].second, loc_end);
      // Compact remaining segments
      uint32_t i2 = i + 1;
      if (i2 < j) {
        for (; j < n_seg; i2++, j++) {
          segs[i2] = segs[j];
        }
        n_seg = i2;
      }
    }

    // If the first segment is the new_data we just received,
    // we can try zero-copy firstly, i.e. send new_data to handler
    // rather than copy it to the buffer first
    // And if the handler does not fully consumed it, we copy the rest
    // to the receiving buffer
    if (segs[0].first == loc && segs[0].second == loc_end) {
      // Try zero-copy processing first
      uint32_t remaining = handler(new_data, new_size);
      segs[0].first = segs[0].second - remaining;
      if (remaining) {
        // Copy remaining data to buffer
        uint32_t consumed = new_size - remaining;
        memcpy(recvbuf + segs[0].first, new_data + consumed, remaining);
      }
    }
    else {
      // Copy data to buffer
      memcpy(recvbuf + loc, new_data, new_size);
      if (i != 0) return false;  // No new contiguous data
      // Process contiguous data from buffer
      uint32_t remaining = handler(recvbuf + segs[0].first, 
                                 segs[0].second - segs[0].first);
      segs[0].first = segs[0].second - remaining;
    }

    // Compact buffer if too much space is wasted
    if (segs[0].first >= BUFSIZE / 2) {
      uint32_t total_size = segs[n_seg - 1].second - segs[0].first;
      if (total_size) {
        memcpy(recvbuf, recvbuf + segs[0].first, total_size);
      }
      uint32_t diff = segs[0].first;
      buf_seq += diff;  // Adjust base sequence
      // Adjust all segments
      for (i = 0; i < n_seg; i++) {
        segs[i].first -= diff;
        segs[i].second -= diff;
      }
    }
    return true;
  }

  /** Ethernet header structure */
  struct EtherHeader
  {
    uint8_t dstMac[6];    // Destination MAC address
    uint8_t srcMac[6];    // Source MAC address
    uint16_t etherType;   // Protocol type (0x0008 for IPv4)
  };

  /** IPv4 header structure */
  struct IpHeader
  {
    uint8_t internetHeaderLength : 4,  // Header length in 32-bit words
            ipVersion : 4;             // IP version (4 for IPv4)
    uint8_t typeOfService;             // QoS/DSCP flags
    uint16_t totalLength;              // Total packet length
    uint16_t ipId;                     // Identification field
    uint16_t fragmentOffset;           // Fragmentation info
    uint8_t timeToLive;                // TTL/hop limit
    uint8_t protocol;                  // Protocol (6 for TCP)
    uint16_t headerChecksum;           // Header checksum
    uint32_t ipSrc;                    // Source IP address
    uint32_t ipDst;                    // Destination IP address
  };

  /** TCP header structure */
  struct TcpHeader
  {
    uint16_t portSrc;                  // Source port
    uint16_t portDst;                  // Destination port
    uint32_t sequenceNumber;           // Sequence number
    uint32_t ackNumber;                // Acknowledgement number
    uint16_t reserved : 4,             // Reserved bits
             dataOffset : 4,           // Header length in 32-bit words
             finFlag : 1,              // FIN flag
             synFlag : 1,              // SYN flag
             rstFlag : 1,              // RST flag
             pshFlag : 1,              // PSH flag
             ackFlag : 1,              // ACK flag
             urgFlag : 1,              // URG flag
             eceFlag : 1,              // ECE flag
             cwrFlag : 1;              // CWR flag
    uint16_t windowSize;               // Receive window size
    uint16_t headerChecksum;           // Checksum
    uint16_t urgentPointer;            // Urgent pointer
  };

  // Header position constants
  static const int IPHeaderPos = sizeof(EtherHeader);  // Ethernet header size
  static const int TcpHeaderPos = IPHeaderPos + sizeof(IpHeader);  // IP + Ethernet

private:
  bool init_stream = false;      // Whether stream is initialized
  uint32_t filter_src_ip;        // Filter: source IP (0 = any)
  uint32_t filter_dst_ip;        // Filter: destination IP (0 = any)
  uint16_t filter_src_port;      // Filter: source port (0 = any)
  uint16_t filter_dst_port;      // Filter: destination port (0 = any)
  uint32_t buf_seq;              // Base sequence number for buffer
  static const int MAX_SEG = 5;  // Maximum number of segments to track
  uint32_t n_seg;                // Current number of segments
  std::pair<uint32_t, uint32_t> segs[MAX_SEG];  // Segment list [start,end)
  uint8_t recvbuf[BUFSIZE];      // Reassembly buffer
};
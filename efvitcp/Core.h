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
#include <arpa/inet.h>
#include <net/if.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <memory>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//#define EFVITCP_DEBUG 0

namespace efvitcp {

// Network protocol constants
static const uint32_t RecvMSS = 1460;        // Maximum Segment Size for receive
static const uint32_t RecvBufSize = 2048;    // Receive buffer size
static const uint32_t TsScale = 20;          // Nanoseconds to milliseconds scale
static const uint32_t TimerSlots = 256;      // Number of timer wheel slots
static const uint32_t TimeWaitTimeout = 60 * 1000; // TIME_WAIT state timeout (ms)
static const uint64_t EmptyKey = (uint64_t)1 << 63; // Marker for empty hash table entry

// Ethernet header structure
struct EtherHeader {
  uint8_t dst_mac[6];  // Destination MAC address
  uint8_t src_mac[6];  // Source MAC address
  uint16_t ether_type; // Ethernet type (e.g., IPv4)
};

// IP header structure
struct IpHeader {
  uint8_t header_len : 4,  // Header length in 32-bit words
          ip_ver : 4;      // IP version (4 for IPv4)
  uint8_t tos;             // Type of service
  uint16_t tot_len;        // Total length
  uint16_t id;             // Identification
  uint16_t frag_offset_flags; // Fragment offset and flags
  uint8_t ttl;            // Time to live
  uint8_t protocol;       // Protocol (6 for TCP)
  uint16_t checksum;      // Header checksum
  uint32_t src_ip;        // Source IP address
  uint32_t dst_ip;        // Destination IP address
};

// TCP header structure
struct TcpHeader {
  uint16_t src_port;      // Source port
  uint16_t dst_port;      // Destination port
  uint32_t seq_num;       // Sequence number
  uint32_t ack_num;       // Acknowledgment number
  union {
    struct {
      uint16_t reserved : 4,  // Reserved bits
                data_offset : 4, // Data offset in 32-bit words
                fin : 1,      // FIN flag
                syn : 1,      // SYN flag
                rst : 1,      // RST flag
                psh : 1,      // PSH flag
                ack : 1;      // ACK flag
    };
    uint16_t offset_flags;   // Combined offset and flags
  };
  uint16_t window_size;   // Window size
  uint16_t checksum;      // Checksum
  uint16_t urgent_pointer; // Urgent pointer
};

// Checksum calculation helper
struct CSum {
  CSum(uint32_t s = 0) : sum(s) {} // Constructor with initial sum

  // Fold 32-bit sum to 16-bit checksum
  inline uint16_t fold() {
    uint32_t res = (sum >> 16) + (sum & 0xffff);
    res += res >> 16;
    return ~res;
  }

  // Add various types to checksum
  inline void add(uint16_t a) { sum += a; }
  inline void add(uint32_t a) {
    sum += a >> 16;
    sum += a & 0xffff;
  }
  inline void add(CSum s) { sum += s.sum; }
  
  // Add buffer of even length
  template<uint32_t Len>
  void add(const void* p) {
    for (uint32_t i = 0; i < Len; i += 2) {
      add(*(uint16_t*)((const char*)p + i));
    }
  }

#ifdef EFVITCP_DEBUG
  // Debug version with runtime length check
  void add(const void* p, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 2) {
      add(*(uint16_t*)((const char*)p + i));
    }
  }
#endif

  // Subtract from checksum
  inline void sub(uint16_t a) {
    sum += 0xffff;
    sum -= a;
  }
  inline void sub(uint32_t a) {
    sum += 0x1fffe;
    sum -= a >> 16;
    sum -= a & 0xffff;
  }

  // Set variable and update checksum
  template<bool reset, typename T>
  void setVar(T& var, T val) {
    if (reset) sub(var);
    var = val;
    add(val);
  }

  uint32_t sum; // Current checksum value
};

#pragma pack(push, 1) // Ensure tight packing of structures

// Receive buffer structure
struct RecvBuf {
  ef_addr post_addr;  // DMA address for receive
  uint16_t __pad;     // Padding for alignment
};

// Send buffer structure
struct SendBuf {
  ef_addr post_addr;  // DMA address for send
  uint32_t send_ts;   // Send timestamp
  bool avail;         // Availability flag
  uint8_t pad;        // Padding
  EtherHeader eth_hdr; // Ethernet header
  IpHeader ip_hdr;    // IP header
  TcpHeader tcp_hdr;  // TCP header

  // Set optional data length and update checksums
  inline void setOptDataLen(uint16_t len, CSum ipsum, CSum tcpsum) {
    ip_hdr.tot_len = htons(40 + len);
    ipsum.add(ip_hdr.tot_len);
    ip_hdr.checksum = ipsum.fold();
    tcpsum.add(htons(20 + len));
    tcp_hdr.checksum = tcpsum.fold();
  }
};

#pragma pack(pop) // Restore default packing

// Generate connection hash key from IP and port
inline uint64_t connHashKey(uint32_t ip, uint16_t port) {
  uint64_t key = ntohl(ip);
  uint64_t p = ntohs(port);
  return (key << 15) | (p & 0x7fff) | ((p & 0x8000) << 32);
}

// Get most significant bit of a number
inline constexpr int getMSB(uint32_t n) {
  return n == 0 ? 0 : getMSB(n >> 1) + 1;
}

// Connection hash table entry
struct ConnHashEntry {
  uint64_t key;      // Connection key
  uint32_t conn_id;  // Connection ID
};

// Timer wheel node for connection timeouts
struct TimerNode {
  TimerNode() : prev(this), next(this) {} // Initialize as self-linked

  bool isUnlinked() { return prev == this; } // Check if node is unlinked

  void unlink() { // Remove from timer wheel
    prev->next = next;
    next->prev = prev;
    prev = next = this;
  }
  
  TimerNode* prev;  // Previous node
  TimerNode* next;  // Next node
  uint32_t conn_id; // Associated connection ID
  uint32_t expire_ts; // Expiration timestamp
};

// TIME_WAIT connection state
struct TimeWaitConn {
  uint8_t dst_mac[6];  // Destination MAC
  bool has_ts;         // Timestamp option flag
  uint32_t dst_ip;     // Destination IP
  uint16_t src_port;   // Source port
  uint16_t dst_port;   // Destination port
  uint32_t seq_num;    // Sequence number
  uint32_t ack_num;    // Acknowledgment number
  uint32_t tsecr;      // Timestamp echo reply
  TimerNode timer;     // Associated timer
};

#ifdef EFVITCP_DEBUG
// Debug function to dump packet information
void dumpPack(IpHeader* ip_hdr) {
  TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);
  uint32_t seq_num = ntohl(tcp_hdr->seq_num) + tcp_hdr->syn;
  uint32_t ack_num = ntohl(tcp_hdr->ack_num);
  cout << "dump Pack: tcp_hdr->syn: " << tcp_hdr->syn << ", tcp_hdr->ack: " << tcp_hdr->ack
        << ", tcp_hdr->fin: " << tcp_hdr->fin << ", tcp_hdr->rst: " << tcp_hdr->rst << ", seq_num: " << seq_num
        << ", ack_num: " << ack_num << ", window_size: " << ntohs(tcp_hdr->window_size)
        << ", src_port: " << htons(tcp_hdr->src_port) << ", dst_port: " << htons(tcp_hdr->dst_port) << endl;
}
#endif

// Main TCP core class template
template<typename Conf>
class Core {
public:
  // Configuration-dependent constants
  static const uint32_t SendBufSize = Conf::SendBuf1K ? 1024 : 2048;
  static const uint32_t MaxSendMTU = SendBufSize - (uint32_t)(offsetof(SendBuf, ip_hdr));
  static const uint32_t SendMTU = MaxSendMTU < 1500 ? MaxSendMTU : 1500;
  static const uint32_t MaxTableSize = 1 << (1 + getMSB(Conf::MaxConnCnt + Conf::MaxTimeWaitConnCnt));
  static const uint32_t TotalTableSize = MaxTableSize + Conf::MaxConnCnt + Conf::MaxTimeWaitConnCnt;

  Core() = default;
  Core(const Core&) = delete;
  Core& operator=(const Core&) = delete;

  ~Core() { destruct(); }

  // Clean up resources
  void destruct() {
    if (dh < 0) return;
    ef_memreg_free(&memreg, dh);
    ef_vi_free(&vi, dh);
    ef_pd_free(&pd, dh);
    ef_driver_close(dh);
    dh = -1;
  }

  // Initialize the TCP stack
  const char* init(const char* interface) {
    destruct();
    now_ts = getns() >> TsScale;
#ifdef EFVITCP_DEBUG
    srand(now_ts);
#endif
    
    // Get local IP address
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface);
    int rc = ioctl(fd, SIOCGIFADDR, &ifr);
    ::close(fd);
    if (rc != 0) return "ioctl SIOCGIFADDR failed";
    local_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    // Initialize EtherFabric driver
    if (ef_driver_open(&dh) < 0) return "ef_driver_open failed";
    if (ef_pd_alloc_by_name(&pd, dh, interface, EF_PD_DEFAULT) < 0) return "ef_pd_alloc_by_name failed";
    
    // Check for CTPIO capability
    int vi_flags = EF_VI_FLAGS_DEFAULT;
    int ifindex = if_nametoindex(interface);
    unsigned long capability_val = 0;
    if (ef_vi_capabilities_get(dh, ifindex, EF_VI_CAP_CTPIO, &capability_val) == 0 && capability_val) {
      use_ctpio = true;
      vi_flags |= EF_VI_TX_CTPIO;
    }
    
    // Allocate virtual interface
    if ((rc = ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, Conf::RecvBufCnt + 1, 
                                  std::min(2048ul, SendBufCnt), NULL, -1,
                                  (enum ef_vi_flags)vi_flags)) < 0)
      return "ef_vi_alloc_from_pd failed";
    
    // Get local MAC address
    ef_vi_get_mac(&vi, dh, local_mac);
    receive_prefix_len = ef_vi_receive_prefix_len(&vi);
    
    // Allocate and align packet buffer
    pkt_buf = (uint8_t*)((uint64_t)(pkt_buf_blk + TotalBufAlign) & ~(TotalBufAlign - 1));
    if (ef_memreg_alloc(&memreg, dh, &pd, dh, pkt_buf, TotalBufSize) < 0) 
      return "ef_memreg_alloc failed";

    // Initialize receive buffers
    for (uint32_t i = 0; i < Conf::RecvBufCnt; i++) {
      RecvBuf* buf = (RecvBuf*)(pkt_buf + i * RecvBufSize);
      buf->post_addr = ef_memreg_dma_addr(&memreg, (uint8_t*)(buf + 1) - pkt_buf);
      if (ef_vi_receive_post(&vi, buf->post_addr, i) < 0) return "ef_vi_receive_post failed";
    }
    
    // Initialize send buffers
    for (uint32_t i = 0; i < SendBufCnt; i++) {
      SendBuf* buf = getSendBuf(i);
      buf->post_addr = ef_memreg_dma_addr(&memreg, (uint8_t*)&buf->eth_hdr - pkt_buf);
      buf->avail = true;
      memcpy(buf->eth_hdr.src_mac, local_mac, 6);
      buf->eth_hdr.ether_type = ntohs(0x0800); // IPv4
      buf->ip_hdr.header_len = 5;
      buf->ip_hdr.ip_ver = 4;
      buf->ip_hdr.tos = 0;
      buf->ip_hdr.id = 0;
      buf->ip_hdr.frag_offset_flags = ntohs(0x4000); // DF flag
      buf->ip_hdr.ttl = 64;
      buf->ip_hdr.protocol = 6; // TCP
      buf->ip_hdr.src_ip = local_ip;
    }
    
    // Initialize RST packet template
    SendBuf* rst = (SendBuf*)(pkt_buf + TotalBufSize - SendBufSize);
    rst_ipsum = 0;
    rst_ipsum.add<sizeof(IpHeader)>(&rst->ip_hdr);
    rst_tcpsum = 0;
    rst_tcpsum.add(rst->ip_hdr.src_ip);
    rst_tcpsum.add(ntohs(0x6)); // TCP protocol
    *(uint32_t*)(rst + 1) = ntohl(0x0101080a); // Timestamp option header

    // Initialize connection tables
    for (uint32_t i = 0; i < Conf::MaxConnCnt; i++) conns[i] = i;
    conn_cnt = 0;
    for (uint32_t i = 0; i < Conf::MaxTimeWaitConnCnt; i++) {
      tw_ids[i] = i;
      TimeWaitConn& tw = tws[i];
      tw.timer.conn_id = Conf::MaxConnCnt + i;
    }
    tw_cnt = 0;
    for (auto& entry : conn_tbl) entry.key = EmptyKey;
    tbl_mask = std::min(MaxTableSize, 128u) - 1;

    return nullptr;
  }

  // Get current time in nanoseconds
  int64_t getns() {
    timespec ts;
    ::clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
  }

  // Remove packet filter
  void delFilter() { ef_vi_filter_del(&vi, dh, &filter_cookie); }

  // Set client-side packet filter
  const char* setClientFilter(uint16_t& local_port_be, uint32_t remote_ip, uint16_t remote_port_be) {
    delFilter();
    bool auto_gen = local_port_be == 0;
    int retries = auto_gen ? 10 : 1;
    const char* err;
    int rc;
    while (retries--) {
      if (auto_gen && (err = autoGetPort(local_port_be))) return err;
      ef_filter_spec filter_spec;
      ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
      if (ef_filter_spec_set_ip4_full(&filter_spec, IPPROTO_TCP, local_ip, local_port_be, remote_ip, remote_port_be) < 0)
        return "ef_filter_spec_set_ip4_full failed";
      if ((rc = ef_vi_filter_add(&vi, dh, &filter_spec, &filter_cookie)) < 0) {
        if (rc == -17) continue; // port exists
        return "ef_vi_filter_add failed";
      }
      return nullptr;
    }
    return "no available port";
  }

  // Automatically get available local port
  const char* autoGetPort(uint16_t& port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return "socket failed";
    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = local_ip;
    local_addr.sin_port = 0; // Let OS choose port
    if (bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
      ::close(fd);
      return "bind failed";
    }
    socklen_t addrlen = sizeof(local_addr);
    getsockname(fd, (struct sockaddr*)&local_addr, &addrlen);
    ::close(fd);
    port = local_addr.sin_port;
    return nullptr;
  }

  // Set server-side packet filter
  const char* setServerFilter(uint16_t local_port_be) {
    delFilter();
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_TCP, local_ip, local_port_be) < 0)
      return "ef_filter_spec_set_ip4_local failed";
    if (ef_vi_filter_add(&vi, dh, &filter_spec, &filter_cookie) < 0) 
      return "ef_vi_filter_add failed";
    return nullptr;
  }

  // Calculate checksum for RST packet
  void sumRst(SendBuf* rst, bool has_ts) {
    CSum ipsum = rst_ipsum;
    ipsum.add(rst->ip_hdr.dst_ip);

    CSum tcpsum = rst_tcpsum;
    tcpsum.add(rst->ip_hdr.dst_ip);
    tcpsum.add(rst->tcp_hdr.src_port);
    tcpsum.add(rst->tcp_hdr.dst_port);
    tcpsum.add(rst->tcp_hdr.seq_num);
    tcpsum.add(rst->tcp_hdr.ack_num);
    tcpsum.add(rst->tcp_hdr.offset_flags);
    if (has_ts) tcpsum.add<12>(rst + 1);
    rst->setOptDataLen(has_ts ? 12 : 0, ipsum, tcpsum);
  }

  // Send RST response to invalid packet
  void rspRst(EtherHeader* eth_hdr) {
    SendBuf* rst = (SendBuf*)(pkt_buf + TotalBufSize - SendBufSize);
    IpHeader* ip_hdr = (IpHeader*)(eth_hdr + 1);
    TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);
    if (tcp_hdr->rst || !rst->avail) return;
    
    // Setup RST packet
    memcpy(rst->eth_hdr.dst_mac, eth_hdr->src_mac, 6);
    rst->ip_hdr.dst_ip = ip_hdr->src_ip;
    rst->tcp_hdr.src_port = tcp_hdr->dst_port;
    rst->tcp_hdr.dst_port = tcp_hdr->src_port;
    rst->tcp_hdr.rst = 1;
    rst->tcp_hdr.data_offset = 5;
    
    // Set sequence number based on ACK flag
    if (tcp_hdr->ack) {
      rst->tcp_hdr.ack = 0;
      rst->tcp_hdr.seq_num = tcp_hdr->ack_num;
    }
    else {
      rst->tcp_hdr.ack = 1;
      rst->tcp_hdr.seq_num = 0;
      uint32_t seg_len = ntohs(ip_hdr->tot_len) - 20 - (tcp_hdr->data_offset << 2) + tcp_hdr->syn + tcp_hdr->fin;
      rst->tcp_hdr.ack_num = htonl(ntohl(tcp_hdr->seq_num) + seg_len);
    }
    sumRst(rst, false);
    send(rst);
  }

  // Send ACK for TIME_WAIT connection
  void ackTW(TimeWaitConn& tw) {
    SendBuf* ack = (SendBuf*)(pkt_buf + TotalBufSize - SendBufSize);
    if (!ack->avail) return;
    
    // Setup ACK packet
    memcpy(ack->eth_hdr.dst_mac, tw.dst_mac, 6);
    ack->ip_hdr.dst_ip = tw.dst_ip;
    ack->tcp_hdr.src_port = tw.src_port;
    ack->tcp_hdr.dst_port = tw.dst_port;
    ack->tcp_hdr.rst = 0;
    ack->tcp_hdr.ack = 1;
    ack->tcp_hdr.seq_num = tw.seq_num;
    ack->tcp_hdr.ack_num = tw.ack_num;
    
    // Handle timestamp option if present
    if (tw.has_ts) {
      ack->tcp_hdr.data_offset = 8;
      uint32_t* opt = (uint32_t*)(ack + 1);
      opt[1] = now_ts;
      opt[2] = tw.tsecr;
    }
    else {
      ack->tcp_hdr.data_offset = 5;
    }
    sumRst(ack, tw.has_ts);
    send(ack);
  }

#ifdef EFVITCP_DEBUG
  // Debug function to validate packet checksums
  void checksum(IpHeader* ip_hdr) {
    TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);
    
    // Verify IP checksum
    CSum sum = 0;
    sum.add<sizeof(IpHeader)>(ip_hdr);
    uint16_t res = sum.fold();
    if (res) {
      cout << "invalid ip sum: " << res << endl;
      exit(1);
    }

    // Verify TCP checksum
    sum = 0;
    sum.add(ip_hdr->src_ip);
    sum.add(ip_hdr->dst_ip);
    sum.add(ntohs(0x6)); // TCP protocol
    uint16_t tcp_len = ntohs(ip_hdr->tot_len) - 20;
    sum.add(htons(tcp_len));
    sum.add(tcp_hdr, tcp_len);
    res = sum.fold();
    if (res) {
      cout << "invalid tcp sum: " << res << endl;
      exit(1);
    }
  }
#endif

  // Send packet to network
  void send(SendBuf* buf) {
    uint32_t send_id = (uint64_t)((uint8_t*)buf - pkt_buf - RecvBufSize * Conf::RecvBufCnt) / SendBufSize;
    uint32_t frame_len = 14 + ntohs(buf->ip_hdr.tot_len);
    
#ifdef EFVITCP_DEBUG
    checksum(&buf->ip_hdr);
    if (rand() % 100 < 3) {
      return; // Simulate 3% packet loss
    }
#endif

    // Use CTPIO if available, fallback to regular transmit
    if (use_ctpio) {
      ef_vi_transmit_ctpio(&vi, &buf->eth_hdr, frame_len, frame_len);
      ef_vi_transmit_ctpio_fallback(&vi, buf->post_addr, frame_len, send_id);
    }
    else {
      ef_vi_transmit(&vi, buf->post_addr, frame_len, send_id);
    }
    buf->avail = false;
  }

  // Poll network events and handle received packets
  template<typename RecvHandler>
  void pollNet(RecvHandler recv_handler) {
    ef_event evs[64];
    ef_request_id tx_ids[EF_VI_TRANSMIT_BATCH];
    int n_ev = ef_eventq_poll(&vi, evs, 64);
    bool received = false;
    
    for (int i = 0; i < n_ev; i++) {
      switch (EF_EVENT_TYPE(evs[i])) {
        case EF_EVENT_TYPE_RX: {
          // Handle received packet
          uint32_t id = EF_EVENT_RX_RQ_ID(evs[i]);
          RecvBuf* buf = (RecvBuf*)(pkt_buf + id * RecvBufSize);
          EtherHeader* eth_hdr = (EtherHeader*)((uint8_t*)(buf + 1) + receive_prefix_len);
          IpHeader* ip_hdr = (IpHeader*)(eth_hdr + 1);
          TcpHeader* tcp_hdr = (TcpHeader*)(ip_hdr + 1);
          
          // Look up connection in hash table
          uint64_t key = connHashKey(ip_hdr->src_ip, tcp_hdr->src_port);
          ConnHashEntry* entry = findConnEntry(key);
          
          // Handle TIME_WAIT state connections
          if (entry->key == key && entry->conn_id >= Conf::MaxConnCnt) {
            TimeWaitConn& tw = tws[entry->conn_id - Conf::MaxConnCnt];
            bool seq_expected = tcp_hdr->seq_num == tw.ack_num;
            
            if (tcp_hdr->rst) {
              if (seq_expected) {
                tw.timer.unlink();
                delConnEntry(key);
              }
            }
            else if (!seq_expected || ntohs(ip_hdr->tot_len) - 20 - (tcp_hdr->data_offset << 2) + 
                     tcp_hdr->syn + tcp_hdr->fin) {
              ackTW(tw);
            }
          }
          else {
            recv_handler(key, entry, eth_hdr);
          }

          ef_vi_receive_init(&vi, buf->post_addr, id);
          received = true;
          break;
        }
        case EF_EVENT_TYPE_RX_DISCARD: {
          // Handle discarded packet
          uint32_t id = EF_EVENT_RX_RQ_ID(evs[i]);
          RecvBuf* buf = (RecvBuf*)(pkt_buf + id * RecvBufSize);
          ef_vi_receive_init(&vi, buf->post_addr, id);
          received = true;
          break;
        }
        case EF_EVENT_TYPE_TX:
        case EF_EVENT_TYPE_TX_ERROR: {
          // Handle transmit completions
          int n_id = ef_vi_transmit_unbundle(&vi, &evs[i], tx_ids);
          for (int i = 0; i < n_id; i++) {
            uint32_t send_id = tx_ids[i];
            getSendBuf(send_id)->avail = true;
          }
          break;
        }
      }
    }
    if (received) ef_vi_receive_push(&vi);
  }

  // Get send buffer by ID
  inline SendBuf* getSendBuf(uint32_t id) {
    return (SendBuf*)(pkt_buf + RecvBufSize * Conf::RecvBufCnt + id * SendBufSize);
  }

  // Find connection entry in hash table
  ConnHashEntry* findConnEntry(uint64_t key) {
    ConnHashEntry* entry = conn_tbl + (key & tbl_mask);
    while (entry->key < key) entry++;
    return entry;
  }

  // Get current hash table size
  uint32_t getTblSize() { return conn_cnt + tw_cnt; }

  // Add new connection to hash table
  void addConnEntry(ConnHashEntry* entry, uint64_t key, uint32_t conn_id) {
    while (entry->key != EmptyKey) {
      std::swap(entry->key, key);
      std::swap(entry->conn_id, conn_id);
      while ((++entry)->key < key)
        ;
    }
    entry->key = key;
    entry->conn_id = conn_id;
    tryExpandConnTbl();
  }

  // Remove connection from hash table
  void delConnEntry(uint64_t key) {
    ConnHashEntry* entry = findConnEntry(key);
#ifdef EFVITCP_DEBUG
    if (entry->key != key) {
      cout << "delConnEntry failed, entry->key: " << entry->key << ", key: " << key << endl;
      printTbl();
      exit(1);
    }
#endif
    // Return connection ID to free list
    if (entry->conn_id < Conf::MaxConnCnt)
      conns[--conn_cnt] = entry->conn_id;
    else
      tw_ids[--tw_cnt] = entry->conn_id - Conf::MaxConnCnt;

    // Remove entry and compact table
    while (true) {
      ConnHashEntry* next = entry + 1;
      while (conn_tbl + (next->key & tbl_mask) > entry) next++;
      if (next->key == EmptyKey) break;
      entry->key = next->key;
      entry->conn_id = next->conn_id;
      entry = next;
    }
    entry->key = EmptyKey;
  }

  // Move connection to TIME_WAIT state
  void enterTW(uint64_t key, SendBuf* buf, bool has_ts, uint32_t tsecr) {
    if (tw_cnt == Conf::MaxTimeWaitConnCnt) {
      delConnEntry(key);
      return;
    }
    
    ConnHashEntry* entry = findConnEntry(key);
#ifdef EFVITCP_DEBUG
    if (entry->key != key) {
      cout << "enterTW failed, entry->key: " << entry->key << ", key: " << key << endl;
      printTbl();
      exit(1);
    }
#endif
    
    // Move connection to TIME_WAIT state
    conns[--conn_cnt] = entry->conn_id;
    uint32_t tw_id = tw_ids[tw_cnt++];
    entry->conn_id = Conf::MaxConnCnt + tw_id;
    
    // Initialize TIME_WAIT connection
    TimeWaitConn& tw = tws[tw_id];
    memcpy(tw.dst_mac, buf->eth_hdr.dst_mac, 6);
    tw.has_ts = has_ts;
    tw.dst_ip = buf->ip_hdr.dst_ip;
    tw.src_port = buf->tcp_hdr.src_port;
    tw.dst_port = buf->tcp_hdr.dst_port;
    tw.seq_num = buf->tcp_hdr.seq_num;
    tw.ack_num = buf->tcp_hdr.ack_num;
    tw.tsecr = tsecr;
    addTimer(TimeWaitTimeout, &tw.timer);
  }

#ifdef EFVITCP_DEBUG
  // Debug function to print hash table
  void printTbl() {
    for (uint32_t i = 0; i <= tbl_mask; i++) {
      ConnHashEntry* entry = conn_tbl + i;
      cout << "i: " << i << ", key: " << entry->key << ", orig_i: " << (entry->key & tbl_mask)
           << ", conn_id: " << entry->conn_id << endl;
    }
  }
#endif

  // Expand hash table if needed
  void tryExpandConnTbl() {
    if (getTblSize() * 2 <= tbl_mask) return;
    
    // Double the table size
    ConnHashEntry* end = conn_tbl + tbl_mask + 1;
    tbl_mask = tbl_mask * 2 + 1;
    ConnHashEntry* new_end = conn_tbl + tbl_mask + 1;
    
    // Move entries to new positions
    while (end->key != EmptyKey) std::swap(*new_end++, *end++);
    
    // Rehash all entries
    auto rehash = [&](ConnHashEntry* entry, uint64_t cnt) {
      for (; cnt; entry++) {
        if (entry->key == EmptyKey) continue;
        ConnHashEntry* new_entry = findConnEntry(entry->key);
        std::swap(entry->key, new_entry->key);
        new_entry->conn_id = entry->conn_id;
        cnt--;
      }
    };
    
    uint64_t end_cnt = new_end - (conn_tbl + tbl_mask + 1);
    rehash(conn_tbl, getTblSize() - end_cnt);
    rehash(conn_tbl + tbl_mask + 1, end_cnt);
  }

  // Add timer to wheel
  void addTimer(uint32_t duration_ts, TimerNode* node) {
    TimerNode* slot;
    if (duration_ts <= TimerSlots) {
      // Short timeout goes to first level wheel
      slot = &timer_slots[0][(now_ts + duration_ts) % TimerSlots];
    }
    else {
      // Long timeout goes to second level wheel
      duration_ts = std::min(duration_ts, TimerSlots * (TimerSlots + 1) - 1 - (now_ts % TimerSlots));
      node->expire_ts = now_ts + duration_ts;
      slot = &timer_slots[1][node->expire_ts / TimerSlots % TimerSlots];
    }
    
    // Insert into timer wheel
    node->next = slot->next;
    node->prev = slot;
    slot->next->prev = node;
    slot->next = node;
  }

  // Poll the timer wheel and handle expired timers
  // Template allows custom handler for timer expiration
  // ns parameter allows passing in current time (for testing), defaults to getting current time
  template<typename TimerHandler>
  void pollTime(TimerHandler handler, int64_t ns = 0) {
    // If no time provided, get current time in nanoseconds
    if (!ns) ns = getns();
    
    // Convert nanoseconds to scaled timestamp units
    uint32_t ts = ns >> TsScale;
    
    // Return if time hasn't advanced since last check
    if (ts == now_ts) return;
    
  #ifdef EFVITCP_DEBUG
    // Debug check for time going backwards (should never happen)
    if ((int)(ts - now_ts) < 0) {
        cout << "time going back!!, ts: " << ts << ", now_ts: " << now_ts << endl;
        exit(1);
    }
  #endif

    // Increment current time and handle timer wheel advancement
    if (++now_ts % TimerSlots == 0) {
        // We've completed a full rotation of the first-level wheel
        // Process the corresponding slot in the second-level wheel
        
        // Get the current slot in second-level wheel
        TimerNode* slot = &timer_slots[1][now_ts / TimerSlots % TimerSlots];
        
        // Process all timers in this slot
        for (TimerNode* node = slot->next; node != slot;) {
            TimerNode* next = node->next;
            
  #ifdef EFVITCP_DEBUG
            // Debug check for invalid expiration times
            if (node->expire_ts - now_ts > 255) {
                cout << "invalid expire_ts: " << node->expire_ts << ", now_ts: " << now_ts 
                      << ", conn_id: " << node->conn_id << endl;
                exit(1);
            }
  #endif
            // Re-add the timer with remaining time (cascading from second to first level)
            addTimer(node->expire_ts - now_ts, node);
            node = next;
        }
        // Reset the slot after processing
        slot->prev = slot->next = slot;
    }

    // Get current slot in first-level wheel
    TimerNode* node = &timer_slots[0][now_ts % TimerSlots];
    
    // Return if no timers in this slot
    if (node->isUnlinked()) return;
    
    // Create a temporary slot to hold expired timers
    TimerNode dump_slot;
    
    // Move all timers from current slot to dump_slot
    dump_slot.next = node->next;
    node->next->prev = node->prev->next = &dump_slot;
    
    // Reset the original slot
    node->prev = node->next = node;
    
    // Process all expired timers
    while ((node = dump_slot.next) != &dump_slot) {
        // Remove timer from dump_slot
        node->unlink();
        
        if (node->conn_id >= Conf::MaxConnCnt) {
            // Handle TIME_WAIT connection expiration
            TimeWaitConn& tw = tws[node->conn_id - Conf::MaxConnCnt];
            delConnEntry(connHashKey(tw.dst_ip, tw.dst_port));
        }
        else {
            // Call handler for regular connection timers
            handler(node);
        }
    }
  }

  // Constants for buffer management
  static const uint64_t SendBufCnt = Conf::ConnSendBufCnt * Conf::MaxConnCnt + 1; // +1 for RST packet
  static const uint64_t TotalBufSize = RecvBufSize * Conf::RecvBufCnt + SendBufSize * SendBufCnt;

  // Determine appropriate buffer alignment based on total size
  // efvi supports specific alignment boundaries (4KB, 64KB, 1MB or 4MB)
  static const uint64_t TotalBufAlign =
    TotalBufSize <= 252444672      ? (1 << 12) :  // 4KB alignment
    (TotalBufSize <= 4039114752    ? (1 << 16) :  // 64KB alignment
    (TotalBufSize <= 64625836032   ? (1 << 20) :  // 1MB alignment
                                    (1 << 22)));  // 4MB alignment

  // Packet buffer storage with required alignment padding
  uint8_t pkt_buf_blk[TotalBufSize + TotalBufAlign] = {};
  uint8_t* pkt_buf;  // Aligned pointer into pkt_buf_blk

  // EtherFabric data structures
  ef_vi vi = {};                 // Virtual interface
  ef_driver_handle dh = -1;      // Driver handle
  ef_pd pd = {};                 // Protection domain
  ef_memreg memreg = {};         // Memory registration
  ef_filter_cookie filter_cookie = {}; // Packet filter

  // Network interface properties
  bool use_ctpio = false;        // CTPIO capability flag
  uint8_t local_mac[6];          // Local MAC address
  uint32_t local_ip;             // Local IP address
  uint32_t receive_prefix_len;   // Receive prefix length

  // Checksum states for RST packets
  CSum rst_ipsum;                // IP checksum state
  CSum rst_tcpsum;               // TCP checksum state

  // Timing and connection management
  uint32_t now_ts;               // Current timestamp (scaled)
  uint32_t conn_cnt;             // Active connection count
  uint32_t conns[Conf::MaxConnCnt]; // Free connection IDs
  uint32_t tw_cnt;               // TIME_WAIT connection count
  uint32_t tw_ids[Conf::MaxTimeWaitConnCnt]; // Free TIME_WAIT IDs
  TimeWaitConn tws[Conf::MaxTimeWaitConnCnt]; // TIME_WAIT connections

  // Connection hash table
  uint64_t tbl_mask;             // Hash table mask
  ConnHashEntry conn_tbl[TotalTableSize]; // Connection hash table

  // Two-level timer wheel (256 slots per level)
  // First level handles timers up to 255 time units
  // Second level handles longer timers up to ~65 seconds
  TimerNode timer_slots[2][TimerSlots];
};

} // namespace efvitcp

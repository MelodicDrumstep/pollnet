# Notes about this Project

This documentation contains my notes on this awesome project for reference and learning purposes. I hope it helps you better understand the project's implementation details.

## Socket

Key interesting findings:

### Polling Mechanism

- Client polls on its connection
- Server polls on all stored connections

### TCP Packet Concatenation Handling

The `SocketTcpConnection` class maintains head and tail pointers to efficiently handle TCP packet concatenation issues.

```cpp
  uint32_t head_;
  uint32_t tail_;
  uint8_t recvbuf_[Conf::RecvBufSize];
```

And the `read` member function is implemented as

```cpp
template<typename Handler>
bool read(Handler handler) {
    // Perform non-blocking read into receive buffer
    int ret = ::read(fd_, recvbuf_ + tail_, Conf::RecvBufSize - tail_);
    
    // Handle read errors/closure
    if (ret <= 0) {
        // EAGAIN means no data available (non-blocking mode)
        if (ret < 0 && errno == EAGAIN) return false;
        // Close connection with appropriate error message
        close(ret < 0 ? "read error" : "remote close", ret < 0);
        return false;
    }

    // Update buffer tail position
    tail_ += ret;

    // Process received data through handler
    uint32_t remaining = handler(recvbuf_ + head_, tail_ - head_);
    
    // Buffer management
    if (remaining == 0) {
        // Reset buffer if all data consumed
        head_ = tail_ = 0;
    }
    else {
        // Move head forward for remaining unprocessed data
        head_ = tail_ - remaining;
        
        // Compact buffer if utilization exceeds 50%
        if (head_ >= Conf::RecvBufSize / 2) {
            memcpy(recvbuf_, recvbuf_ + head_, remaining);
            head_ = 0;
            tail_ = remaining;
        }
        // Handle buffer overflow
        else if (tail_ == Conf::RecvBufSize) {
            close("recv buf full");
        }
    }
    return true;
}
```

Once receiving new data into the receive buffer, we:

1. Update the tail pointer
2. Pass the data to the input handler (callback function)

The handler may either:
- Fully consume the data: We reset both head and tail pointers to 0
- Partially consume the data: We advance the head pointer accordingly

When buffer space becomes limited, we perform compaction by copying remaining data to the head of the receive buffer.

### Deletion by Swapping

The `SocketTcpServer` class maintains

```cpp
    Conn* conns_[Conf::MaxConns];            // Array of connection pointers
    // maintain the Conn* inside a seperate array for lightweight deletion of Connections
    // If we want to delete a random connection "i", we just use
    // std::swap(conns_[i], conns_[--conns_cnt]) without 
    Conn conns_data_[Conf::MaxConns];        // Actual connection objects
```

The deletion is performed by swapping the connection pointer with the tail pointer, without immediate resource cleanup.

```cpp
        // Poll existing connections
        for (uint32_t i = 0; i < conns_cnt_;) {
            Conn& conn = *conns_[i];
            conn.pollConn(now, handler);
            if (conn.isConnected())
                i++;
            else {
                // Remove disconnected connection and notify handler
                std::swap(conns_[i], conns_[--conns_cnt_]);
                handler.onTcpDisconnect(conn);
            }
        }
```

## TCP Stream

Key implementation details:

### Reassembler Implementation Using Flat Array and Interval List

The `TcpStream` class maintains

```cpp
  uint32_t buf_seq;              // Base sequence number for buffer
  uint32_t n_seg;                // Current number of segments
  std::pair<uint32_t, uint32_t> segs[MAX_SEG];  // Segment list [start,end)
  uint8_t recvbuf[BUFSIZE];      // Reassembly buffer
```

When receiving new data, avoid immediately copying it to the receive buffer to enable zero-copy optimization. The procedure is:

1. First update and merge intervals in the interval list
2. Check if the consumption interval exactly matches the new data:
   - If matched: Directly pass the data to the handler without buffer copying
     - For partial consumption: Copy only the remaining portion to the receive buffer
   - Otherwise: Copy the data to the receive buffer before handler processing

## Efvi Udp Receiver

Implementation workflow:

1. Initialize using the API

2. Memory allocation:
   - Allocate DMA-accessible user-space memory using `mmap` or `posix_memalign`
   - Enable huge pages to minimize TLB misses
   - Register the memory with the API

```cpp
    // Allocate packet buffers (prefer huge pages)
    size_t alloc_size = N_BUF * PKT_BUF_SIZE;
    buf_mmapped = true;
    pkt_bufs = (uint8_t*)mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, 
                             MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (pkt_bufs == MAP_FAILED) {
      buf_mmapped = false;
      rc = posix_memalign((void**)&pkt_bufs, 4096, alloc_size);
      if (rc != 0) {
        saveError("posix_memalign failed", -rc);
        return false;
      }
    }

    // Register memory with NIC
    if ((rc = ef_memreg_alloc(&memreg, dh, &pd, dh, pkt_bufs, alloc_size)) < 0) {
      saveError("ef_memreg_alloc failed", rc);
      return false;
    }
```

Then register the memory space for NIC DMA operations and populate the post address field in the packet space. Ensure DMA addresses are cacheline-aligned before posting the buffer space to the RX queue.

```cpp
    // Initialize receive buffers
    for (int i = 0; i < N_BUF; i++) {
      struct pkt_buf* pkt_buf = (struct pkt_buf*)(pkt_bufs + i * PKT_BUF_SIZE);
      // Reserve cache line for DMA address
      pkt_buf->post_addr = ef_memreg_dma_addr(&memreg, i * PKT_BUF_SIZE) + 64;
      // Post buffer to receive queue
      if ((rc = ef_vi_receive_post(&vi, pkt_buf->post_addr, i)) < 0) {
        saveError("ef_vi_receive_post failed", rc);
        return false;
      }
    }
```

3. RX Queue Polling:
   - **Standard Buffer Mode**:
     1. Locate the corresponding pkg_buf
     2. Deliver data to the handler
     3. Repost the buffer to the RX queue for reuse
   - **X3 Direct Mode**:
     - Use `efct_vi_rxpkt_get` for packet retrieval


```cpp
    // Poll for received packets (non-blocking)
    if (ef_eventq_poll(&vi, &evs, 1) == 0) return false;

    int type = EF_EVENT_TYPE(evs);
    bool ret = false;

    if (pkt_bufs) {
      // Standard buffer mode (non-X3 NICs)
      int id = EF_EVENT_RX_RQ_ID(evs);
      struct pkt_buf* pkt_buf = (struct pkt_buf*)(pkt_bufs + id * PKT_BUF_SIZE);

      if (type == EF_EVENT_TYPE_RX) {
        // Calculate UDP payload location and length:
        // - data points to UDP payload (after all headers)
        // - length is extracted from UDP header (converted from network byte order)
        const uint8_t* data = (const uint8_t*)pkt_buf + udp_prefix_len;
        uint16_t len = ntohs(*(uint16_t*)(data - 4)) - 8;
        
        // Call handler with received data
        handler(data, len);
        ret = true;
      }
      
      // Repost buffer to receive queue
      ef_vi_receive_post(&vi, pkt_buf->post_addr, id);
    }
```

## Efvi Udp Sender

Implementation workflow:

1. Initialization:
   - Resolve destination MAC address:
     - Primary method: ARP table lookup
     - Fallback: Use gateway MAC address
   - Configure multicast settings if required

2. Memory Preparation:
   - Allocate user-space DMA-accessible memory via `mmap`/`posix_memalign`
   - Enable huge pages to optimize TLB performance
   - Register memory with the API

```cpp
    // Standard mode uses pre-allocated packet buffers
    size_t alloc_size = N_BUF * PKT_BUF_SIZE;
    s.x2.buf_index = 0;
    s.x2.buf_mmapped = true;
    
    // Try to allocate huge pages for better performance
    s.x2.pkt_bufs = (uint8_t*)mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
    if (s.x2.pkt_bufs == MAP_FAILED) {
        s.x2.buf_mmapped = false;
        // Fall back to regular aligned memory
        rc = posix_memalign((void**)&s.x2.pkt_bufs, 4096, alloc_size);
        if (rc != 0) {
            saveError("posix_memalign failed", -rc);
            return false;
        }
    }

    // Register memory region with NIC for DMA
    if ((rc = ef_memreg_alloc(&s.x2.memreg, dh, &pd, dh, s.x2.pkt_bufs, alloc_size)) < 0) {
        saveError("ef_memreg_alloc failed", rc);
        return false;
    }
```

    - Precompute checksums and prepare common UDP packet headers

```cpp
    // Initialize UDP packet template
    uint8_t eth[42];
    init_udp_pkt(eth, local_addr, local_mac, dest_addr, dest_mac);

    // Precompute IP checksum components for fast updates
    uint16_t* ip4 = (uint16_t*)(eth + 14);
    ipsum_cache = 0;
    for (int i = 0; i < 10; i++) {
        ipsum_cache += ip4[i];
    }
    ipsum_cache = (ipsum_cache >> 16u) + (ipsum_cache & 0xffff);
    ipsum_cache += (ipsum_cache >> 16u);
```

    - Register DMA space and populate post address fields and pre-copy common headers into packets to reduce runtime overhead

```cpp
    // Initialize all packet buffers with template
    for (int i = 0; i < N_BUF; i++) {
        struct pkt_buf* pkt = (struct pkt_buf*)(s.x2.pkt_bufs + i * PKT_BUF_SIZE);
        // Set DMA address (with alignment padding)
        pkt->post_addr = ef_memreg_dma_addr(&s.x2.memreg, i * PKT_BUF_SIZE) + sizeof(ef_addr);
        // Copy template headers
        memcpy(&(pkt->eth), eth, 42);
    }
```

3. Transmission Process:
   - Copy payload data into UDP packets
   - Transmit using:
     - `ef_vi_transmit_ctpio` (primary)
     - `ef_vi_transmit_ctpio_fallback` (alternative)
   - Poll for unprocessed transmission events

```cpp
    bool write(const void* data, uint32_t size) {
        if (is_x3) return writeX3(data, size);
        
        // Get next available buffer (round-robin)
        struct pkt_buf* pkt = (struct pkt_buf*)(s.x2.pkt_bufs + s.x2.buf_index * PKT_BUF_SIZE);
        
        // Update packet headers with current size
        update_udp_pkt(&pkt->eth, size);
        
        // Copy payload data into packet buffer
        memcpy(pkt + 1, data, size);
        
        // Transmit packet using CTPIO if available
        uint32_t frame_len = 42 + size;
        ef_vi_transmit_ctpio(&vi, &pkt->eth, frame_len, 64);
        
        // Fallback to standard transmit if needed
        int rc = ef_vi_transmit_ctpio_fallback(&vi, pkt->post_addr, frame_len, s.x2.buf_index);
        
        // Advance buffer index
        s.x2.buf_index = (s.x2.buf_index + 1) % N_BUF;

        // Process any completion events
        ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
        ef_request_id ids[EF_VI_TRANSMIT_BATCH];
        int events = ef_eventq_poll(&vi, evs, EF_VI_EVENT_POLL_MIN_EVS);
        for (int i = 0; i < events; ++i) {
            if (EF_EVENT_TYPE_TX == EF_EVENT_TYPE(evs[i])) {
                ef_vi_transmit_unbundle(&vi, &evs[i], ids);
            }
        }
        return rc == 0;
    }
```

## Efvi TCP Client

It's a clever design: the handler callback function is implemented in the `Client` class, which stores both a `efvitcp::TCPClient` object and a `TcpClient::Conn` object. The `poll` function looks like this:

```cpp
// Process network events
void poll() {
    client.poll(*this);
}
```

So, now the `Client` class serves as the handler class!
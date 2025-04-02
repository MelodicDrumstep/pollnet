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
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/capabilities.h>
#include <etherfabric/efct_vi.h>
#include <arpa/inet.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/**
 * Base class for Solarflare EF_VI network receivers
 * Provides common initialization and buffer management
 */
class EfviReceiver
{
public:
  /// Returns last error message
  const char* getLastError() { return last_error_; };

  /// Checks if receiver is closed
  bool isClosed() { return dh < 0; }

protected:
  /**
   * Initialize EF_VI receiver
   * @param interface Network interface name to bind to
   * @return true on success, false on failure
   */
  bool init(const char* interface) {
    int rc;
    // Open Solarflare driver
    if ((rc = ef_driver_open(&dh)) < 0) {
      saveError("ef_driver_open failed", rc);
      return false;
    }
    // Allocate protection domain
    if ((rc = ef_pd_alloc_by_name(&pd, dh, interface, EF_PD_DEFAULT)) < 0) {
      saveError("ef_pd_alloc_by_name failed", rc);
      return false;
    }

    // Allocate virtual interface (VI)
    if ((rc = ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, N_BUF, 0, NULL, -1, EF_VI_FLAGS_DEFAULT)) < 0) {
      saveError("ef_vi_alloc_from_pd failed", rc);
      return false;
    }

    // Check for X3 NIC (different buffer handling)
    if (ef_vi_receive_fill_level(&vi) > 0) return true; // is_x3

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
    return true;
  }

  /// Save error message with optional error code
  void saveError(const char* msg, int rc) {
    snprintf(last_error_, sizeof(last_error_), "%s %s", msg, rc < 0 ? (const char*)strerror(-rc) : "");
  }

  /// Close receiver and free resources
  void close() {
    if (dh >= 0) {
      ef_driver_close(dh);
      dh = -1;
    }
    if (pkt_bufs) {
      if (buf_mmapped) {
        munmap(pkt_bufs, N_BUF * PKT_BUF_SIZE);
      }
      else {
        free(pkt_bufs);
      }
      pkt_bufs = nullptr;
    }
  }

  static const int N_BUF = 511;      // Number of receive buffers
  static const int PKT_BUF_SIZE = 2048; // Size of each buffer

  /// Packet buffer structure
  struct pkt_buf {
    ef_addr post_addr;  // DMA address for posting
  };

  struct ef_vi vi;       // Virtual interface
  uint8_t* pkt_bufs = nullptr; // Packet buffers

  ef_driver_handle dh = -1;  // Driver handle
  struct ef_pd pd;           // Protection domain
  struct ef_memreg memreg;   // Memory registration
  bool buf_mmapped;          // Whether using huge pages
  char last_error_[64] = ""; // Last error message
};

/**
 * UDP Receiver implementation using Solarflare EF_VI (Ethernet Fabric Virtual Interface)
 * This class provides high-performance UDP packet reception capabilities using Solarflare NICs
 */
class EfviUdpReceiver : public EfviReceiver
{
public:
  /**
   * Initialize the UDP receiver with specific network parameters
   * @param interface Network interface name (e.g., "eth0")
   * @param dest_ip Destination IP address to filter for (in dotted-quad notation)
   * @param dest_port Destination UDP port to filter for (host byte order)
   * @param subscribe_ip Multicast group IP to join (optional, empty string for unicast)
   * @return true if initialization succeeded, false on error (check getLastError())
   *
   * Initialization sequence:
   * 1. Sets up base EF_VI receiver infrastructure
   * 2. Configures hardware filtering for specified UDP traffic
   * 3. Optionally joins multicast group if subscribe_ip provided
   */
  bool init(const char* interface, const char* dest_ip, uint16_t dest_port, const char* subscribe_ip = "") {
    // First initialize the base receiver functionality
    if (!EfviReceiver::init(interface)) {
      return false;
    }

    // Calculate offset to UDP payload in received packets:
    // 64 bytes - buffer alignment padding
    // + ef_vi_receive_prefix_len() - NIC-specific receive prefix
    // + 14 bytes - Ethernet header
    // + 20 bytes - IP header
    // + 8 bytes - UDP header
    udp_prefix_len = 64 + ef_vi_receive_prefix_len(&vi) + 14 + 20 + 8;

    int rc;
    ef_filter_spec filter_spec;
    struct sockaddr_in sa_local;
    
    // Convert port to network byte order and IP to binary form
    sa_local.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &(sa_local.sin_addr));
    
    // Initialize filter specification for hardware filtering
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    
    // Set up filter for specified UDP/IP traffic
    if ((rc = ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, 
                                          sa_local.sin_addr.s_addr, sa_local.sin_port)) < 0) {
      saveError("ef_filter_spec_set_ip4_local failed", rc);
      return false;
    }
    
    // Install the filter on the virtual interface
    if ((rc = ef_vi_filter_add(&vi, dh, &filter_spec, NULL)) < 0) {
      saveError("ef_vi_filter_add failed", rc);
      return false;
    }

    // Handle multicast subscription if requested
    if (subscribe_ip[0]) {
      // Create UDP socket for multicast group management
      if ((subscribe_fd_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        saveError("socket failed", -errno);
        return false;
      }

      // Set up multicast group parameters
      struct ip_mreq group;
      inet_pton(AF_INET, subscribe_ip, &(group.imr_interface));
      inet_pton(AF_INET, dest_ip, &(group.imr_multiaddr));
      
      // Join the multicast group
      if (setsockopt(subscribe_fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                    (char*)&group, sizeof(group)) < 0) {
        saveError("setsockopt IP_ADD_MEMBERSHIP failed", -errno);
        return false;
      }
    }

    return true;
  }

  /**
   * Destructor - ensures proper cleanup of resources
   */
  ~EfviUdpReceiver() { close("destruct"); }

  /**
   * Close the receiver and release resources
   * @param reason Description of why the receiver is being closed
   */
  void close(const char* reason) {
    // Clean up multicast subscription socket if active
    if (subscribe_fd_ >= 0) {
      saveError(reason, 0);
      ::close(subscribe_fd_);
      subscribe_fd_ = -1;
    }
    // Delegate to base class for common cleanup
    EfviReceiver::close();
  }

  /**
   * Read and process incoming UDP packets
   * @tparam Handler Type of callback function (must accept (const uint8_t* data, uint32_t len))
   * @param handler Callback function to process received packets
   * @return true if a packet was processed, false if no packets were available
   *
   * Operation:
   * 1. Polls the event queue for received packets (non-blocking)
   * 2. For each received packet:
   *    a. Extracts UDP payload
   *    b. Calls handler with payload data and length
   *    c. Reposts buffer or releases packet
   * 3. Returns immediately if no packets available
   */
  template<typename Handler>
  bool read(Handler handler) {
    ef_event evs;
    
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
    else {
      // X3 direct mode (for X3-series NICs)
      if (type == EF_EVENT_TYPE_RX_REF) {
        // Get packet data (offset by 42 bytes to skip headers)
        const uint8_t* data = (const uint8_t*)efct_vi_rxpkt_get(&vi, evs.rx_ref.pkt_id) + 42;
        uint16_t len = ntohs(*(uint16_t*)(data - 4)) - 8;
        
        // Call handler with received data
        handler(data, len);
        ret = true;
      }
      
      // Release packet buffer
      efct_vi_rxpkt_release(&vi, evs.rx_ref.pkt_id);
    }
    
    return ret;
  }

private:
  int udp_prefix_len;       // Byte offset to UDP payload in received packets
  int subscribe_fd_ = -1;   // Socket file descriptor for multicast subscription
};

/**
 * Ethernet Frame Receiver using Solarflare EF_VI
 * Provides raw Ethernet frame reception with hardware acceleration
 */
class EfviEthReceiver : public EfviReceiver
{
public:
    /**
     * Initialize the Ethernet receiver
     * @param interface Network interface name (e.g., "eth0")
     * @param promiscuous If true, receives all frames on the wire (not just addressed to this host)
     * @return true on success, false on failure (check getLastError())
     */
    bool init(const char* interface, bool promiscuous = false) {
        // First initialize base receiver components
        if (!EfviReceiver::init(interface)) {
            return false;
        }

        // Get NIC-specific receive prefix length (metadata added by NIC)
        rx_prefix_len = ef_vi_receive_prefix_len(&vi);

        int rc;
        ef_filter_spec fs;
        // Initialize empty filter specification
        ef_filter_spec_init(&fs, EF_FILTER_FLAG_NONE);
        
        // Configure promiscuous mode setting
        if ((rc = ef_filter_spec_set_port_sniff(&fs, (int)promiscuous)) < 0) {
            saveError("ef_filter_spec_set_port_sniff failed", rc);
            return false;
        }
        
        // Apply filter to virtual interface
        if ((rc = ef_vi_filter_add(&vi, dh, &fs, NULL)) < 0) {
            saveError("ef_vi_filter_add failed", rc);
            return false;
        }

        return true;
    }

    /**
     * Destructor - ensures proper cleanup of resources
     */
    ~EfviEthReceiver() { close(); }

    /**
     * Close the receiver and free resources
     */
    void close() { 
        // Delegate to base class for common cleanup
        EfviReceiver::close(); 
    }

    /**
     * Read and process incoming Ethernet frames
     * @tparam Handler Callback type (void(const uint8_t* data, uint32_t len))
     * @param handler Callback function that processes received frames
     * @return true if a frame was processed, false if no frames available
     */
    template<typename Handler>
    bool read(Handler handler) {
        ef_event evs;
        // Non-blocking poll for received frames
        if (ef_eventq_poll(&vi, &evs, 1) == 0) return false;

        int type = EF_EVENT_TYPE(evs);
        bool ret = false;

        if (pkt_bufs) {
            // Standard buffer mode processing
            int id = EF_EVENT_RX_RQ_ID(evs);
            struct pkt_buf* pkt_buf = (struct pkt_buf*)(pkt_bufs + id * PKT_BUF_SIZE);
            
            if (type == EF_EVENT_TYPE_RX) {
                // Calculate frame start (after alignment and NIC metadata)
                const uint8_t* data = (const uint8_t*)pkt_buf + 64 + rx_prefix_len;
                // Get actual frame length (subtracting NIC metadata)
                uint32_t len = EF_EVENT_RX_BYTES(evs) - rx_prefix_len;
                
                // Invoke handler with frame data
                handler(data, len);
            }
            // Return buffer to receive queue
            ef_vi_receive_post(&vi, pkt_buf->post_addr, id);
        }
        else {
            // X3 direct mode processing
            if (type == EF_EVENT_TYPE_RX_REF) {
                // Get direct pointer to packet data
                const uint8_t* data = (const uint8_t*)efct_vi_rxpkt_get(&vi, evs.rx_ref.pkt_id);
                uint16_t len = evs.rx_ref.len;
                handler(data, len);
                ret = true;
            }
            // Release packet buffer
            efct_vi_rxpkt_release(&vi, evs.rx_ref.pkt_id);
        }
        return ret;
    }

private:
    int rx_prefix_len;  // Length of NIC-specific receive metadata prefix
};

/**
 * High-performance UDP Sender using Solarflare EF_VI
 * Supports both unicast and multicast with hardware checksum offload
 */
class EfviUdpSender
{
public:
    /**
     * Initialize UDP sender with network parameters
     * @param interface Network interface name (e.g., "eth0")
     * @param local_ip Source IP address in dotted-quad notation
     * @param local_port Source UDP port (host byte order)
     * @param dest_ip Destination IP address
     * @param dest_port Destination UDP port (host byte order)
     * @return true on success, false on failure (check getLastError())
     */
    bool init(const char* interface, const char* local_ip, uint16_t local_port, 
             const char* dest_ip, uint16_t dest_port) {
        // Initialize address structures
        struct sockaddr_in local_addr, dest_addr;
        uint8_t local_mac[6], dest_mac[6];
        
        // Convert ports to network byte order
        local_addr.sin_port = htons(local_port);
        dest_addr.sin_port = htons(dest_port);
        
        // Convert IP strings to binary form
        inet_pton(AF_INET, local_ip, &(local_addr.sin_addr));
        inet_pton(AF_INET, dest_ip, &(dest_addr.sin_addr));

        // Handle MAC address resolution
        if ((0xff & dest_addr.sin_addr.s_addr) < 224) { // unicast address
            char dest_mac_addr[64];
            // Try to get MAC from ARP cache
            if (!getMacFromARP(interface, dest_ip, dest_mac_addr)) {
                char gw[64];
                // Fall back to gateway MAC if destination not in ARP cache
                if (!getGW(dest_ip, gw) || !getMacFromARP(interface, gw, dest_mac_addr)) {
                    saveError("Can't find dest ip from arp cache, please ping dest ip first", 0);
                    return false;
                }
            }
            // Validate MAC address format (XX:XX:XX:XX:XX:XX)
            if (strlen(dest_mac_addr) != 17) {
                saveError("invalid dest_mac_addr", 0);
                return false;
            }
            // Convert textual MAC to binary representation
            for (int i = 0; i < 6; ++i) {
                dest_mac[i] = hexchartoi(dest_mac_addr[3 * i]) * 16 + 
                              hexchartoi(dest_mac_addr[3 * i + 1]);
            }
        }
        else { // multicast address
            // Standard multicast MAC prefix (01:00:5e)
            dest_mac[0] = 0x1;
            dest_mac[1] = 0;
            dest_mac[2] = 0x5e;
            // Last 3 bytes derived from IP (23 bits of IP mapped to MAC)
            dest_mac[3] = 0x7f & (dest_addr.sin_addr.s_addr >> 8);
            dest_mac[4] = 0xff & (dest_addr.sin_addr.s_addr >> 16);
            dest_mac[5] = 0xff & (dest_addr.sin_addr.s_addr >> 24);
        }

        // Initialize EF_VI driver
        int rc;
        if ((rc = ef_driver_open(&dh)) < 0) {
            saveError("ef_driver_open failed", rc);
            return false;
        }
        // Allocate protection domain
        if ((rc = ef_pd_alloc_by_name(&pd, dh, interface, EF_PD_DEFAULT)) < 0) {
            saveError("ef_pd_alloc_by_name failed", rc);
            return false;
        }

        // Check for X3 NIC capabilities (different optimization path)
        int ifindex = if_nametoindex(interface);
        unsigned long val = 0;
        if (ef_vi_capabilities_get(dh, ifindex, EF_VI_CAP_CTPIO_ONLY, &val) == 0 && val) {
            is_x3 = true;
        }

        // Allocate virtual interface with appropriate parameters
        if ((rc = ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, 0, is_x3 ? -1 : N_BUF, NULL, -1,
                                      EF_VI_TX_CTPIO)) < 0) {
            saveError("ef_vi_alloc_from_pd failed", rc);
            return false;
        }
        // Get local MAC address for packet headers
        ef_vi_get_mac(&vi, dh, local_mac);

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

        // Initialize buffers based on NIC type
        if (is_x3) {
            // X3 mode uses direct I/O with pre-built headers
            memcpy(s.x3.eth, eth, 42);
        }
        else {
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

            // Initialize all packet buffers with template
            for (int i = 0; i < N_BUF; i++) {
                struct pkt_buf* pkt = (struct pkt_buf*)(s.x2.pkt_bufs + i * PKT_BUF_SIZE);
                // Set DMA address (with alignment padding)
                pkt->post_addr = ef_memreg_dma_addr(&s.x2.memreg, i * PKT_BUF_SIZE) + sizeof(ef_addr);
                // Copy template headers
                memcpy(&(pkt->eth), eth, 42);
            }
        }

        return true;
    }

    /**
     * Destructor - ensures proper cleanup
     */
    ~EfviUdpSender() { close(); }

    /**
     * Get last error message
     * @return null-terminated error string
     */
    const char* getLastError() { return last_error_; };

    /**
     * Check if sender is closed
     * @return true if closed, false if active
     */
    bool isClosed() { return dh < 0; }

    /**
     * Close the sender and release all resources
     */
    void close() {
        if (dh >= 0) {
            ef_driver_close(dh);
            dh = -1;
        }
        if (!is_x3) {
            if (s.x2.pkt_bufs) {
                if (s.x2.buf_mmapped) {
                    munmap(s.x2.pkt_bufs, N_BUF * PKT_BUF_SIZE);
                }
                else {
                    free(s.x2.pkt_bufs);
                }
                s.x2.pkt_bufs = nullptr;
            }
        }
    }

    /**
     * Send UDP packet
     * @param data Pointer to payload data
     * @param size Payload size in bytes
     * @return true if packet was queued successfully
     */
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

private:
    /**
     * X3-specific optimized transmission path
     * @param data Payload data pointer
     * @param size Payload size in bytes
     * @return true if packet was queued successfully
     */
    bool writeX3(const void* data, uint32_t size) {
        // Update packet headers with current size
        update_udp_pkt(s.x3.eth, size);

        // Use scatter/gather I/O (header + payload in separate buffers)
        struct iovec iov[2] = {{s.x3.eth, 42}, {(void*)data, size}};
        ef_vi_transmitv_ctpio(&vi, 42 + size, iov, 2, 0);

        // Poll for completion events (non-blocking)
        ef_event evs[EF_VI_EVENT_POLL_MIN_EVS];
        ef_eventq_poll(&vi, evs, EF_VI_EVENT_POLL_MIN_EVS);
        return true;
    }

    /**
     * Look up MAC address from ARP cache
     * @param interface Network interface name
     * @param dest_ip IP address to look up
     * @param dest_mac Output buffer for MAC (must be at least 18 bytes)
     * @return true if found, false if not in cache
     */
    bool getMacFromARP(const char* interface, const char* dest_ip, char* dest_mac) {
        FILE* arp_file = fopen("/proc/net/arp", "r");
        if (!arp_file) {
            saveError("Can't open /proc/net/arp", -errno);
            return false;
        }
        
        char header[1024];
        if (!fgets(header, sizeof(header), arp_file)) {
            saveError("Invalid file /proc/net/arp", 0);
            fclose(arp_file);
            return false;
        }
        
        // Parse ARP cache entries
        char ip[64], hw[64], device[64];
        while (3 == fscanf(arp_file, "%63s %*s %*s %63s %*s %63s", ip, hw, device)) {
            if (!strcmp(ip, dest_ip) && !strcmp(interface, device)) {
                strcpy(dest_mac, hw);
                fclose(arp_file);
                return true;
            }
        }
        fclose(arp_file);
        return false;
    }

    /**
     * Get gateway IP for a destination
     * @param ip Destination IP address
     * @param gw Output buffer for gateway IP
     * @return true if route found, false otherwise
     */
    bool getGW(const char* ip, char* gw) {
        char buf[1024];
        sprintf(buf, "/usr/sbin/ip route get %s", ip);
        FILE* pipe = popen(buf, "r");
        if (!pipe) return false;
        
        while (fgets(buf, sizeof(buf), pipe)) {
            if (sscanf(buf, "%*s via %s", gw) == 1) {
                pclose(pipe);
                return true;
            }
        }
        pclose(pipe);
        return false;
    }

    /**
     * Save error message with system error information
     * @param msg Description of error
     * @param rc Error code (negative for system errors)
     */
    void saveError(const char* msg, int rc) {
        snprintf(last_error_, sizeof(last_error_), "%s %s", msg, 
                rc < 0 ? strerror(-rc) : "");
    }

    /**
     * Convert hex character to numeric value
     * @param c Input character (0-9, a-f, A-F)
     * @return Numeric value (0-15)
     */
    uint8_t hexchartoi(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return 0;
    }

    // Packet header structures (packed to avoid alignment padding)
    #pragma pack(push, 1)
    struct ci_ether_hdr {
        uint8_t ether_dhost[6];  // Destination MAC
        uint8_t ether_shost[6];  // Source MAC
        uint16_t ether_type;     // EtherType (0x0800 for IPv4)
    };

    struct ci_ip4_hdr {
        uint8_t ip_ihl_version;   // Version (4) + header length (in 32-bit words)
        uint8_t ip_tos;           // Type of service
        uint16_t ip_tot_len_be16; // Total length (network byte order)
        uint16_t ip_id_be16;      // Identification
        uint16_t ip_frag_off_be16; // Fragment offset
        uint8_t ip_ttl;           // Time to live
        uint8_t ip_protocol;      // Protocol (6=TCP, 17=UDP)
        uint16_t ip_check_be16;   // Header checksum
        uint32_t ip_saddr_be32;   // Source address
        uint32_t ip_daddr_be32;   // Destination address
    };

    struct ci_udp_hdr {
        uint16_t udp_source_be16;  // Source port
        uint16_t udp_dest_be16;    // Destination port
        uint16_t udp_len_be16;     // Length (header + payload)
        uint16_t udp_check_be16;   // Checksum
    };

    struct pkt_buf {
        ef_addr post_addr;      // DMA address for posting
        ci_ether_hdr eth;       // Ethernet header
        ci_ip4_hdr ip4;         // IP header
        ci_udp_hdr udp;         // UDP header
    };
    #pragma pack(pop)

    /**
     * Initialize UDP packet template
     * @param buf Buffer to fill with headers
     * @param local_addr Local socket address
     * @param local_mac Local MAC address
     * @param dest_addr Destination socket address
     * @param dest_mac Destination MAC address
     */
    void init_udp_pkt(void* buf, struct sockaddr_in& local_addr, uint8_t* local_mac, 
                     struct sockaddr_in& dest_addr, uint8_t* dest_mac) {
        struct ci_ether_hdr* eth = (struct ci_ether_hdr*)buf;
        struct ci_ip4_hdr* ip4 = (struct ci_ip4_hdr*)(eth + 1);
        struct ci_udp_hdr* udp = (struct ci_udp_hdr*)(ip4 + 1);

        // Set up Ethernet header
        eth->ether_type = htons(0x0800);  // IPv4
        memcpy(eth->ether_shost, local_mac, 6);
        memcpy(eth->ether_dhost, dest_mac, 6);

        // Initialize IP header
        ci_ip4_hdr_init(ip4, 0, 0, 0, IPPROTO_UDP, 
                        local_addr.sin_addr.s_addr, dest_addr.sin_addr.s_addr);
        
        // Initialize UDP header
        ci_udp_hdr_init(udp, ip4, local_addr.sin_port, dest_addr.sin_port, 0);
    }

    /**
     * Update UDP packet headers for new payload size
     * @param buf Packet buffer containing headers
     * @param paylen New payload length in bytes
     */
    inline void update_udp_pkt(void* buf, uint32_t paylen) {
        struct ci_ether_hdr* eth = (struct ci_ether_hdr*)buf;
        struct ci_ip4_hdr* ip4 = (struct ci_ip4_hdr*)(eth + 1);
        struct ci_udp_hdr* udp = (struct ci_udp_hdr*)(ip4 + 1);
        
        // Update IP total length
        uint16_t iplen = htons(28 + paylen);  // 20B IP + 8B UDP + payload
        ip4->ip_tot_len_be16 = iplen;
        
        // Update IP checksum using precomputed components
        uint32_t ipsum = ipsum_cache + iplen;
        ipsum += (ipsum >> 16u);
        ip4->ip_check_be16 = ~ipsum & 0xffff;
        
        // Update UDP length
        udp->udp_len_be16 = htons(8 + paylen);
    }

    /**
     * Initialize IPv4 header fields
     * @param ip Pointer to IP header
     * @param opts_len Length of IP options in bytes
     * @param tot_len Total packet length
     * @param id_be16 Identification field
     * @param protocol IP protocol number
     * @param saddr_be32 Source address
     * @param daddr_be32 Destination address
     */
    void ci_ip4_hdr_init(struct ci_ip4_hdr* ip, int opts_len, int tot_len, 
                        int id_be16, int protocol, unsigned saddr_be32,
                        unsigned daddr_be32) {
        #define CI_IP4_IHL_VERSION(ihl) ((4u << 4u) | ((ihl) >> 2u))
        ip->ip_ihl_version = CI_IP4_IHL_VERSION(sizeof(*ip) + opts_len);
        ip->ip_tos = 0;
        ip->ip_tot_len_be16 = htons(tot_len);
        ip->ip_id_be16 = id_be16;
        ip->ip_frag_off_be16 = 0x0040;  // Don't fragment flag
        ip->ip_ttl = 64;
        ip->ip_protocol = protocol;
        ip->ip_saddr_be32 = saddr_be32;
        ip->ip_daddr_be32 = daddr_be32;
        ip->ip_check_be16 = 0;  // Checksum calculated later
    }

    /**
     * Initialize UDP header fields
     * @param udp Pointer to UDP header
     * @param ip Associated IP header
     * @param sport_be16 Source port
     * @param dport_be16 Destination port
     * @param payload_len Length of payload in bytes
     */
    void ci_udp_hdr_init(struct ci_udp_hdr* udp, struct ci_ip4_hdr* ip, 
                        unsigned sport_be16, unsigned dport_be16,
                        int payload_len) {
        udp->udp_source_be16 = sport_be16;
        udp->udp_dest_be16 = dport_be16;
        udp->udp_len_be16 = htons(sizeof(*udp) + payload_len);
        udp->udp_check_be16 = 0;  // Optional for IPv4
    }

    // Constants
    static const int N_BUF = 128;          // Number of packet buffers
    static const int PKT_BUF_SIZE = 2048;  // Size of each buffer

    // EF_VI components
    struct ef_vi vi;          // Virtual interface
    ef_driver_handle dh = -1; // Driver handle
    struct ef_pd pd;          // Protection domain

    // Checksum optimization
    uint32_t ipsum_cache;     // Precomputed IP checksum components
    bool is_x3 = false;       // Whether using X3 optimized path

    // Buffer management (variant for X2 vs X3 NICs)
    union {
        struct {  // X2 buffer mode
            uint8_t* pkt_bufs;     // Packet buffer array
            uint32_t buf_index;    // Current buffer index
            bool buf_mmapped;      // Whether using huge pages
            struct ef_memreg memreg; // Memory registration
        } x2;
        struct {  // X3 direct mode
            uint8_t eth[42];       // Pre-built headers
        } x3;
    } s;

    char last_error_[64] = ""; // Last error message
};
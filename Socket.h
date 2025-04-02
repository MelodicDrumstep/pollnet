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
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <memory>
#include <limits>

/**
 * @brief Base TCP Connection class template
 * Handles individual TCP connection state and operations
 * @tparam Conf Configuration struct containing connection parameters
 */
template<typename Conf>
class SocketTcpConnection : public Conf::UserData
{
public:
  ~SocketTcpConnection() { close("destruct"); }

  /**
   * @brief Get the last error message
   * @return const char* Error message string
   */
  const char* getLastError() { return last_error_; };

  /**
   * @brief Check if connection is active
   * @return bool True if connection is established
   */
  bool isConnected() { return fd_ >= 0; }

  /**
   * @brief Get peer address information
   * @param addr Output parameter to store peer address
   * @return bool Success status
   */
  bool getPeername(struct sockaddr_in& addr) {
    socklen_t addr_len = sizeof(addr);
    return ::getpeername(fd_, (struct sockaddr*)&addr, &addr_len) == 0;
  }

  /**
   * @brief Close the connection with a reason
   * @param reason Error message describing reason for closure
   * @param check_errno Whether to check system errno
   */
  void close(const char* reason, bool check_errno = false) {
    if (fd_ >= 0) {
      saveError(reason, check_errno);
      ::close(fd_);
      fd_ = -1;
    }
  }

  /**
   * @brief Write some data to the connection
   * @param data Data buffer to send
   * @param size Size of data
   * @param more Flag indicating if more data will follow
   * @return int Number of bytes sent or -1 on error
   */
  int writeSome(const void* data, uint32_t size, bool more = false) {
    int flags = MSG_NOSIGNAL;
    if (more) flags |= MSG_MORE;
    int ret = ::send(fd_, data, size, flags);
    if (ret < 0) {
      if (errno == EAGAIN)
        ret = 0;
      else
        close("send error", true);
    }
    if (Conf::SendTimeoutSec) send_ts_ = time(0);
    return ret;
  }

  /**
   * @brief Write all data to the connection (blocking)
   * @param data Data buffer to send
   * @param size Size of data
   * @param more Flag indicating if more data will follow
   * @return bool Success status
   */
  bool write(const void* data_, uint32_t size, bool more = false) {
    const uint8_t* data = (const uint8_t*)data_;
    do {
      int sent = writeSome(data, size, more);
      if (sent < 0) return false;
      data += sent;
      size -= sent;
    } while (size != 0);
    return true;
  }

  /**
   * @brief Write data non-blocking
   * @param data Data buffer to send
   * @param size Size of data
   * @param more Flag indicating if more data will follow
   * @return bool Success status
   */
  bool writeNonblock(const void* data, uint32_t size, bool more = false) {
    if (writeSome(data, size, more) != (int)size) {
      close("send error", true);
      return false;
    }
    return true;
  }

protected:
  template<typename ServerConf>
  friend class SocketTcpServer;

  /**
   * @brief Establish a TCP connection to a remote server
   * 
   * @param server_addr Remote server address structure containing IP and port
   * @param local_port_be Local port in network byte order (big-endian) to bind to.
   *                      If 0, system will assign a random port
   * @return bool True if connection was successfully established, false otherwise
   */
  bool connect(struct sockaddr_in& server_addr, uint16_t local_port_be) {
    // Create a new TCP socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      saveError("socket error", true);
      return false;
    }

    // If a specific local port was requested, bind to it
    if (local_port_be) {
      struct sockaddr_in local_addr;
      local_addr.sin_family = AF_INET;
      local_addr.sin_addr.s_addr = INADDR_ANY;  // Bind to all available interfaces
      local_addr.sin_port = local_port_be;      // Use specified port
      if (::bind(fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        saveError("bind error", true);
        ::close(fd);
        return false;
      }
    }

    // Attempt to connect to the remote server
    if (::connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      saveError("connect error", true);
      ::close(fd);
      return false;
    }

    // Initialize the connection with current timestamp and socket descriptor
    return open(time(0), fd);
  }

/**
 * @brief Poll connection for events and handle timeouts
 * @tparam Handler Handler class implementing timeout callbacks
 * @param now Current timestamp in seconds
 * @param handler Reference to handler instance
 */
template<typename Handler>
void pollConn(int64_t now, Handler& handler) {
    // Check for send timeout if configured
    if (Conf::SendTimeoutSec && now >= send_ts_ + Conf::SendTimeoutSec) {
        // Invoke send timeout callback
        handler.onSendTimeout(*this);
        // Update last send timestamp to current time
        send_ts_ = now;
    }

    // Attempt to read data from socket
    bool got_data = read([&](const uint8_t* data, uint32_t size) { 
        // Forward received data to handler
        return handler.onTcpData(*this, data, size);
    });

    // Process receive timeout if configured
    if (Conf::RecvTimeoutSec) {
        // Trigger timeout if no data received and expiration time reached
        if (!got_data && now >= expire_ts_) {
            handler.onRecvTimeout(*this);
            got_data = true; // Mark as handled
        }
        // Reset expiration time if data was received
        if (got_data) expire_ts_ = now + Conf::RecvTimeoutSec;
    }
}

/**
 * @brief Read data from socket and process via handler
  It will be called by "pollConn", and the handler object for this class
  would be a lambda expression, which is
    [&](const uint8_t* data, uint32_t size) { 
          // Forward received data to handler
          return handler.onTcpData(*this, data, size); 
      }
 * @tparam Handler Callback function type
 * @param handler Data processing callback
 * @return bool True if data was successfully read and processed
 */
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

/**
 * @brief Initialize new connection state
 * @param now Current timestamp in seconds
 * @param fd Connected socket file descriptor
 * @return bool True if initialization succeeded
 */
bool open(int64_t now, int fd) {
    // Set basic connection parameters
    fd_ = fd;
    head_ = tail_ = 0; // Reset buffer positions
    send_ts_ = now; // Initialize send timestamp
    expire_ts_ = now + Conf::RecvTimeoutSec; // Set initial receive timeout

    // Configure non-blocking mode
    int flags = fcntl(fd_, F_GETFL, 0);
    if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        close("fcntl O_NONBLOCK error", true);
        return false;
    }

    // Enable TCP_NODELAY (disable Nagle's algorithm)
    int yes = 1;
    if (setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
        close("setsockopt TCP_NODELAY error", true);
        return false;
    }

    return true;
}

  void saveError(const char* msg, bool check_errno) {
    snprintf(last_error_, sizeof(last_error_), "%s %s", msg, check_errno ? (const char*)strerror(errno) : "");
  }

  int fd_ = -1;
  int64_t send_ts_ = 0;
  int64_t expire_ts_ = 0;
  uint32_t head_;
  uint32_t tail_;
  uint8_t recvbuf_[Conf::RecvBufSize];
  char last_error_[64] = "";
};

/**
 * @brief TCP Client implementation with automatic reconnection support
 * @tparam Conf Configuration struct containing:
 *   - RecvBufSize: Size of receive buffer
 *   - ConnRetrySec: Reconnection retry interval
 *   - SendTimeoutSec: Send operation timeout
 *   - RecvTimeoutSec: Receive operation timeout
 *   - UserData: User-defined data structure
 */
template<typename Conf>
class SocketTcpClient : public SocketTcpConnection<Conf>
{
public:
    using Conn = SocketTcpConnection<Conf>;

  /**
  * @brief Initialize the TCP client
  * @param interface Network interface name (optional for socket implementation)
  * @param server_ip Target server IP address
  * @param server_port Target server port
  * @param local_port Local port to bind to (0 for automatic)
  * @return bool Success status
  */
  bool init(const char* interface, const char* server_ip, uint16_t server_port,
            uint16_t local_port = 0) {
      // Set the address family to IPv4 (AF_INET)
      server_addr_.sin_family = AF_INET;

      // Convert the server IP from string format (e.g., "192.168.1.1") 
      // to binary network byte order and store it in server_addr_.sin_addr
      inet_pton(AF_INET, server_ip, &(server_addr_.sin_addr));

      // Convert the server port from host byte order to network byte order (big-endian)
      // and store it in server_addr_.sin_port
      server_addr_.sin_port = htons(server_port);

      // Zero out the remaining padding bytes in the sockaddr_in structure
      // (This is a legacy requirement for compatibility)
      bzero(&(server_addr_.sin_zero), 8);

      // Convert the local port to network byte order and store it for later use
      // (If local_port is 0, the OS will assign an ephemeral port during bind())
      local_port_be_ = htons(local_port);

      // Return true indicating initialization was successful
      // (Note: This is a simplified example; real code might validate inputs or check for errors)
      return true;
  }

    /**
     * @brief Enable reconnection attempt
     * Resets the reconnection timer to allow immediate reconnect attempt
     */
    void allowReconnect() { next_conn_ts_ = 0; }

    /**
     * @brief Poll for events and handle connection state
     * @tparam Handler Event handler class type
     * @param handler Event handler instance with callbacks:
     *   - onTcpConnected(Conn&)
     *   - onTcpConnectFailed()
     *   - onTcpDisconnect(Conn&)
     */
    template<typename Handler>
    void poll(Handler& handler) {
        int64_t now = time(0);
        if (!this->isConnected()) {
            // Handle reconnection logic
            if (now < next_conn_ts_) return;
            if (Conf::ConnRetrySec)
                next_conn_ts_ = now + Conf::ConnRetrySec;
            else
                // Disable auto-reconnect if ConnRetrySec is 0
                next_conn_ts_ = std::numeric_limits<int64_t>::max();
            
            if (!this->connect(server_addr_, local_port_be_)) {
                handler.onTcpConnectFailed();
                return;
            }
            handler.onTcpConnected(*this);
        }
        
        // Handle established connection events
        this->pollConn(now, handler);
        if (!this->isConnected()) handler.onTcpDisconnect(*this);
    }

private:
    int64_t next_conn_ts_ = 0;           // Next connection attempt timestamp
    struct sockaddr_in server_addr_;      // Server address information
    uint16_t local_port_be_;             // Local port in network byte order
};

/**
 * @brief TCP Server implementation supporting multiple client connections
 * @tparam Conf Configuration struct containing:
 *   - RecvBufSize: Size of receive buffer per connection
 *   - MaxConns: Maximum number of simultaneous connections
 *   - SendTimeoutSec: Send operation timeout
 *   - RecvTimeoutSec: Receive operation timeout
 *   - UserData: User-defined data structure
 */
template<typename Conf>
class SocketTcpServer
{
public:
    using Conn = SocketTcpConnection<Conf>;

    /**
     * @brief Initialize the TCP server
     * @param interface Network interface name (optional for socket implementation)
     * @param server_ip Server IP address to bind to
     * @param server_port Server port to listen on
     * @return bool Success status
     */
    bool init(const char* interface, const char* server_ip, uint16_t server_port) {
        // Initialize connection pool
        for (uint32_t i = 0; i < Conf::MaxConns; i++) conns_[i] = conns_data_ + i;
        
        // Create listening socket
        listenfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listenfd_ < 0) {
            saveError("socket error");
            return false;
        }

        // Set socket to non-blocking mode
        int flags = fcntl(listenfd_, F_GETFL, 0);
        if (fcntl(listenfd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            close("fcntl O_NONBLOCK error");
            return false;
        }

        // Enable address reuse
        int yes = 1;
        if (setsockopt(listenfd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            close("setsockopt SO_REUSEADDR error");
            return false;
        }

        // Bind to specified address and port
        struct sockaddr_in local_addr;
        local_addr.sin_family = AF_INET;
        inet_pton(AF_INET, server_ip, &(local_addr.sin_addr));
        local_addr.sin_port = htons(server_port);
        bzero(&(local_addr.sin_zero), 8);
        if (bind(listenfd_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            close("bind error");
            return false;
        }

        // Start listening for connections
        if (listen(listenfd_, 5) < 0) {
            close("listen error");
            return false;
        }

        return true;
    }

    /**
     * @brief Get current number of active connections
     * @return uint32_t Number of active connections
     */
    uint32_t getConnCnt() { return conns_cnt_; }

    /**
     * @brief Iterate over all active connections
     * @tparam Handler Connection handler function type
     * @param handler Handler function (void(Conn&))
     */
    template<typename Handler>
    void foreachConn(Handler handler) {
        for (uint32_t i = 0; i < conns_cnt_; i++) {
            Conn& conn = *conns_[i];
            handler(conn);
        }
    }

    /**
     * @brief Close the server and cleanup resources
     * @param reason Reason for closure
     */
    void close(const char* reason) {
        if (listenfd_ >= 0) {
            saveError(reason);
            ::close(listenfd_);
            listenfd_ = -1;
        }
    }

    /**
     * @brief Get last error message
     * @return const char* Error message string
     */
    const char* getLastError() { return last_error_; };

    ~SocketTcpServer() { close("destruct"); }

    /**
     * @brief Check if server is closed
     * @return bool True if server socket is closed
     */
    bool isClosed() { return listenfd_ < 0; }

    /**
     * @brief Poll for new connections and handle existing connections
     * @tparam Handler Event handler class with callbacks:
     *   - onTcpConnected(Conn&)
     *   - onTcpDisconnect(Conn&)
     * @param handler Event handler instance
     */
    template<typename Handler>
    void poll(Handler& handler) {
        int64_t now = time(0);
        // Accept new connections if not at capacity
        if (conns_cnt_ < Conf::MaxConns) {
            Conn& conn = *conns_[conns_cnt_];
            struct sockaddr_in clientaddr;
            socklen_t addr_len = sizeof(clientaddr);
            int fd = ::accept(listenfd_, (struct sockaddr*)&(clientaddr), &addr_len);
            if (fd >= 0 && conn.open(now, fd)) {
                conns_cnt_++;
                handler.onTcpConnected(conn);
            }
        }

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
    }

private:
    /**
     * @brief Save error message with errno details
     * @param msg Base error message
     */
    void saveError(const char* msg) { 
        snprintf(last_error_, sizeof(last_error_), "%s %s", msg, strerror(errno)); 
    }

    int listenfd_ = -1;                      // Listening socket descriptor
    uint32_t conns_cnt_ = 0;                 // Current number of active connections
    Conn* conns_[Conf::MaxConns];            // Array of connection pointers
    // maintain the Conn* inside a seperate array for lightweight deletion of Connections
    // If we want to delete a random connection "i", we just use
    // std::swap(conns_[i], conns_[--conns_cnt]) without 
    Conn conns_data_[Conf::MaxConns];        // Actual connection objects
    char last_error_[64] = "";               // Last error message buffer
};

/**
 * @brief UDP Receiver implementation
 * Handles UDP packet reception with optional multicast support.
 * @tparam RecvBufSize Size of the receive buffer (default is 1500 bytes)
 */
template<uint32_t RecvBufSize = 1500>
class SocketUdpReceiver
{
public:
    /**
     * @brief Initialize the UDP receiver
     * Sets up the UDP socket, binds it to the destination IP and port, and optionally joins a multicast group.
     * 
     * @param interface Network interface name (currently unused)
     * @param dest_ip Destination IP address to bind the receiver to
     * @param dest_port Destination port to bind the receiver to
     * @param subscribe_ip Multicast group IP address to join (optional). If provided, the receiver will join the multicast group
     * @return bool Returns true if initialization is successful, false otherwise
     */
    bool init(const char* interface, const char* dest_ip, uint16_t dest_port, const char* subscribe_ip = "") {
        // Create a UDP socket
        if ((fd_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            saveError("socket error");
            return false;
        }

        // Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            close("fcntl O_NONBLOCK error");
            return false;
        }

        // Enable address reuse
        int optval = 1;
        if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, (const void*)&optval, sizeof(int)) < 0) {
            close("setsockopt SO_REUSEADDR error");
            return false;
        }

        // Bind to the specified address
        struct sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(dest_port);
        inet_pton(AF_INET, dest_ip, &(servaddr.sin_addr));
        if (bind(fd_, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            close("bind failed");
            return false;
        }

        // Set up multicast if requested
        if (subscribe_ip[0]) {
            struct ip_mreq group;
            inet_pton(AF_INET, subscribe_ip, &(group.imr_interface));
            inet_pton(AF_INET, dest_ip, &(group.imr_multiaddr));

            if (setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) < 0) {
                close("setsockopt IP_ADD_MEMBERSHIP failed");
                return false;
            }
        }

        return true;
    }

    /**
     * @brief Destructor for the UDP receiver
     * Closes the socket and cleans up resources.
     */
    ~SocketUdpReceiver() { close("destruct"); }

    /**
     * @brief Get the local port to which the receiver is bound
     * Retrieves the port number that the receiver is currently bound to.
     * 
     * @return uint16_t The local port number
     */
    uint16_t getLocalPort() {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        getsockname(fd_, (struct sockaddr*)&addr, &addrlen);
        return ntohs(addr.sin_port);
    }

    /**
     * @brief Get the last error message
     * Retrieves the last error message that was recorded during socket operations.
     * 
     * @return const char* The error message
     */
    const char* getLastError() { return last_error_; };

    /**
     * @brief Check if the socket is closed
     * Determines whether the UDP receiver's socket is currently closed.
     * 
     * @return bool Returns true if the socket is closed, false otherwise
     */
    bool isClosed() { return fd_ < 0; }

    /**
     * @brief Close the socket and release resources
     * Closes the socket and records the reason for closure. 
     * 
     * @param reason The reason for closing the socket (for logging purposes)
     */
    void close(const char* reason) {
        if (fd_ >= 0) {
            saveError(reason);
            ::close(fd_);
            fd_ = -1;
        }
    }

    /**
     * @brief Read data from the UDP socket
     * Reads data from the socket and calls the provided handler function with the received data.
     * 
     * @tparam Handler A function or callable type that will handle the received data
     * @param handler The function to handle the data
     * @return bool Returns true if data was successfully read and processed, false otherwise
     */
    template<typename Handler>
    bool read(Handler handler) {
        int n = ::read(fd_, buf, RecvBufSize);
        if (n > 0) {
            handler(buf, n);
            return true;
        }
        return false;
    }

    /**
     * @brief Receive data from a specific source (with address information)
     * Receives a UDP packet from a remote sender and passes the data along with sender address to the handler.
     * 
     * @tparam Handler A function or callable type that will handle the received data
     * @param handler The function to handle the data, which will receive data, size, and sender's address
     * @return bool Returns true if data was successfully received and processed, false otherwise
     */
    template<typename Handler>
    bool recvfrom(Handler handler) {
        struct sockaddr_in src_addr;
        socklen_t addrlen = sizeof(src_addr);
        int n = ::recvfrom(fd_, buf, RecvBufSize, 0, (struct sockaddr*)&src_addr, &addrlen);
        if (n > 0) {
            handler(buf, n, src_addr);
            return true;
        }
        return false;
    }

    /**
     * @brief Send data to a specific destination
     * Sends a UDP packet to a specified destination address.
     * 
     * @param data Pointer to the data to be sent
     * @param size Size of the data to be sent
     * @param dst_addr The destination address where the data will be sent
     * @return bool Returns true if the data was successfully sent, false otherwise
     */
    bool sendto(const void* data, uint32_t size, const sockaddr_in& dst_addr) {
        return ::sendto(fd_, data, size, 0, (const struct sockaddr*)&dst_addr, sizeof(dst_addr)) == size;
    }

private:
    /**
     * @brief Save the last error message
     * Records the error message and the associated system error string (from `errno`).
     * 
     * @param msg The error message to be saved
     */
    void saveError(const char* msg) { snprintf(last_error_, sizeof(last_error_), "%s %s", msg, strerror(errno)); }

    int fd_ = -1;                      /**< Socket file descriptor */
    uint8_t buf[RecvBufSize];           /**< Buffer to store incoming data */
    char last_error_[64] = "";          /**< Last error message */
};


/**
 * @brief UDP Sender implementation
 * Handles UDP packet transmission with configurable source and destination
 */
class SocketUdpSender
{
public:
    /**
     * @brief Initialize UDP sender
     * @param interface Network interface name (optional for socket implementation)
     * @param local_ip Local IP address to bind to
     * @param local_port Local port to bind to
     * @param dest_ip Destination IP address for packets
     * @param dest_port Destination port for packets
     * @return bool Success status
     */
    bool init(const char* interface, const char* local_ip, uint16_t local_port, 
             const char* dest_ip, uint16_t dest_port) {
        // Create UDP socket
        if ((fd_ = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            saveError("socket error");
            return false;
        }

        // Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            close("fcntl O_NONBLOCK error");
            return false;
        }

        // Bind to local address
        struct sockaddr_in localaddr;
        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = htons(local_port);
        inet_pton(AF_INET, local_ip, &(localaddr.sin_addr));
        if (bind(fd_, (const struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
            close("bind failed");
            return false;
        }

        // Connect to destination address (for send() usage)
        struct sockaddr_in destaddr;
        memset(&destaddr, 0, sizeof(destaddr));
        destaddr.sin_family = AF_INET;
        destaddr.sin_port = htons(dest_port);
        inet_pton(AF_INET, dest_ip, &(destaddr.sin_addr));
        if (::connect(fd_, (struct sockaddr*)&destaddr, sizeof(destaddr)) < 0) {
            close("connect error");
            return false;
        }

        return true;
    }

    ~SocketUdpSender() { close("destruct"); }

    /**
     * @brief Get the local port being used
     * @return uint16_t Local port number in host byte order
     */
    uint16_t getLocalPort() {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        getsockname(fd_, (struct sockaddr*)&addr, &addrlen);
        return ntohs(addr.sin_port);
    }

    /**
     * @brief Get last error message
     * @return const char* Error message string
     */
    const char* getLastError() { return last_error_; };

    /**
     * @brief Check if sender is closed
     * @return bool True if socket is closed
     */
    bool isClosed() { return fd_ < 0; }

    /**
     * @brief Close the UDP sender
     * @param reason Reason for closure
     */
    void close(const char* reason) {
        if (fd_ >= 0) {
            saveError(reason);
            ::close(fd_);
            fd_ = -1;
        }
    }

    /**
     * @brief Send data to pre-configured destination
     * @param data Data buffer to send
     * @param size Size of data
     * @return bool True if entire data was sent
     */
    bool write(const void* data, uint32_t size) { 
        return ::send(fd_, data, size, 0) == size; 
    }

private:
    /**
     * @brief Save error message with errno details
     * @param msg Base error message
     */
    void saveError(const char* msg) { 
        snprintf(last_error_, sizeof(last_error_), "%s %s", msg, strerror(errno)); 
    }

    int fd_ = -1;                    // Socket file descriptor
    char last_error_[64] = "";       // Error message buffer
};

/**
 * @brief Ethernet Frame Receiver
 * Handles raw ethernet frame reception with promiscuous mode support
 * @tparam RecvBufSize Size of receive buffer (default 1500 bytes)
 */
template<uint32_t RecvBufSize = 1500>
class SocketEthReceiver
{
public:
    /**
     * @brief Initialize ethernet receiver
     * @param interface Network interface name to bind to
     * @param promiscuous Enable promiscuous mode to receive all packets
     * @return bool Success status
     */
    bool init(const char* interface, bool promiscuous = false) {
        // Create raw socket for ethernet frames
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0) {
            saveError("socket error");
            return false;
        }

        // Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            close("fcntl O_NONBLOCK error");
            return false;
        }

        // Bind to specific interface
        struct sockaddr_ll socket_address;
        memset(&socket_address, 0, sizeof(socket_address));
        socket_address.sll_family = PF_PACKET;
        socket_address.sll_ifindex = if_nametoindex(interface);
        socket_address.sll_protocol = htons(ETH_P_ALL);

        if (bind(fd_, (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            close("bind error");
            return false;
        }

        // Enable promiscuous mode if requested
        if (promiscuous) {
            struct packet_mreq mreq = {0};
            mreq.mr_ifindex = if_nametoindex(interface);
            mreq.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                close("setsockopt PACKET_ADD_MEMBERSHIP");
                return false;
            }
        }
        return true;
    }

    ~SocketEthReceiver() { close("destruct"); }

    /**
     * @brief Get last error message
     * @return const char* Error message string
     */
    const char* getLastError() { return last_error_; };

    /**
     * @brief Close the ethernet receiver
     * @param reason Reason for closure
     */
    void close(const char* reason) {
        if (fd_ >= 0) {
            saveError(reason);
            ::close(fd_);
            fd_ = -1;
        }
    }

    /**
     * @brief Read and process an ethernet frame
     * @tparam Handler Frame handler function type
     * @param handler Handler function (void(const uint8_t*, uint32_t))
     * @return bool True if frame was read and processed
     */
    template<typename Handler>
    bool read(Handler handler) {
        int n = ::read(fd_, buf, RecvBufSize);
        if (n > 0) {
            handler(buf, n);
            return true;
        }
        return false;
    }

private:
    /**
     * @brief Save error message with errno details
     * @param msg Base error message
     */
    void saveError(const char* msg) { 
        snprintf(last_error_, sizeof(last_error_), "%s %s", msg, strerror(errno)); 
    }

    int fd_ = -1;                    // Socket file descriptor
    uint8_t buf[RecvBufSize];        // Receive buffer
    char last_error_[64] = "";       // Error message buffer
};


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
#include <string.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <zf/zf.h>
#include <time.h>
#include <memory>
#include <limits>

namespace {
// Global flag to track if zf library is initialized
bool _zf_inited = false;

// Initializes the zf library if not already done
int _zf_init() {
  if (!_zf_inited) {
    int rc = zf_init();  // Initialize ZeroFriction stack
    if (rc < 0) {
      return rc;  // Return error code if initialization fails
    }
    _zf_inited = true;  // Mark as initialized
  }
  return 0;  // Success
}
} // namespace

/* 
TCP Connection class using ZeroFriction library
- Template parameter Conf provides configuration settings
- Inherits from Conf::UserData for custom user data storage
*/
template<typename Conf>
class TcpdirectTcpConnection : public Conf::UserData
{
public:
  ~TcpdirectTcpConnection() { close("destruct"); }

  // Returns last error message
  const char* getLastError() { return last_error_; };

  // Checks if connection is established
  bool isConnected() { 
    return zock_ && zft_state(zock_) == TCP_ESTABLISHED; 
  }

  // Gets peer's address information
  bool getPeername(struct sockaddr_in& addr) {
    socklen_t addr_len = sizeof(addr);
    zft_getname(zock_, nullptr, nullptr, (struct sockaddr*)&addr, &addr_len);
    return true;
  }

  // Closes the connection with given reason
  void close(const char* reason) {
    if (zock_) {
      saveError(reason, 0);  // Save error message
      zft_free(zock_);      // Free ZeroFriction socket
      zock_ = nullptr;      // Clear socket pointer
    }
  }

  // Writes some data (may not send entire buffer)
  int writeSome(const void* data, uint32_t size, bool more = false) {
    int flags = 0;
    if (more) flags |= MSG_MORE;  // Set MORE flag if needed
    
    // Send data using ZeroFriction
    int sent = zft_send_single(zock_, data, size, flags);
    
    if (sent < 0) {
      // Handle non-fatal errors
      if (sent == -EAGAIN || sent == -ENOMEM)
        sent = 0;  // Treat as temporary failure
      else
        saveError("zft_send_single error", sent);
    }
    
    // Update last send timestamp if timeout is configured
    if (Conf::SendTimeoutSec) send_ts_ = time(0);
    return sent;
  }

  // Writes all data (blocks until complete or error)
  bool write(const void* data_, uint32_t size, bool more = false) {
    const uint8_t* data = (const uint8_t*)data_;
    int flags = 0;
    if (more) flags |= MSG_MORE;
    
    // Keep sending until all data is transmitted
    do {
      int sent = writeSome(data, size, more);
      if (sent < 0) return false;  // Error case
      data += sent;  // Advance buffer pointer
      size -= sent;  // Decrement remaining size
    } while (size != 0);
    return true;
  }

  // Non-blocking write attempt (fails if can't send immediately)
  bool writeNonblock(const void* data, uint32_t size, bool more = false) {
    if (writeSome(data, size, more) != (int)size) {
      close("zft_send_single failed");
      return false;
    }
    return true;
  }

protected:
  // Allow server class to access protected members
  template<typename ServerConf>
  friend class TcpdirectTcpServer;

  // Establishes connection to server
  bool connect(struct zf_attr* attr, struct sockaddr_in& server_addr, 
               uint16_t local_port_be) {
    int rc;
    struct zft_handle* tcp_handle;
    
    // Allocate TCP handle
    if ((rc = zft_alloc(stack_, attr, &tcp_handle)) < 0) {
      saveError("zft_alloc error", rc);
      return false;
    }

    // Bind to local port if specified
    if (local_port_be) {
      struct sockaddr_in local_addr;
      local_addr.sin_family = AF_INET;
      local_addr.sin_addr.s_addr = INADDR_ANY;
      local_addr.sin_port = local_port_be;
      
      if ((rc = zft_addr_bind(tcp_handle, (struct sockaddr*)&local_addr, 
                             sizeof(local_addr), 0)) < 0) {
        saveError("bind error", rc);
        zft_handle_free(tcp_handle);
        return false;
      }
    }

    // Initiate connection
    if ((rc = zft_connect(tcp_handle, (struct sockaddr*)&server_addr, 
                         sizeof(server_addr), &zock_)) < 0) {
      saveError("zft_connect error", rc);
      zft_handle_free(tcp_handle);
      return false;
    }
    
    // Wait for connection to complete
    while (zft_state(zock_) == TCP_SYN_SENT) 
      zf_reactor_perform(stack_);
    
    // Verify connection succeeded
    if (zft_state(zock_) != TCP_ESTABLISHED) {
      saveError("zft_state error", 0);
      return false;
    }
    
    // Initialize connection state
    open(time(0), zock_, stack_);
    return true;
  }

  // Poll connection for events
  template<typename Handler>
  void pollConn(int64_t now, Handler& handler) {
    // Check for send timeout
    if (Conf::SendTimeoutSec && now >= send_ts_ + Conf::SendTimeoutSec) {
      handler.onSendTimeout(*this);
      send_ts_ = now;
    }
    
    // Read available data
    bool got_data = read([&](const uint8_t* data, uint32_t size) { 
      return handler.onTcpData(*this, data, size); 
    });
    
    // Check for receive timeout
    if (Conf::RecvTimeoutSec) {
      if (!got_data && now >= expire_ts_) {
        handler.onRecvTimeout(*this);
        got_data = true;
      }
      if (got_data)
        expire_ts_ = now + Conf::RecvTimeoutSec;
    }
  }

  // Reads data from connection and invokes handler
  template<typename Handler>
  bool read(Handler handler) {
    // Message buffer with iovec for scatter/gather I/O
    struct {
      uint8_t msg[sizeof(struct zft_msg)]; // Prevent GCC flexible array warning
      struct iovec iov;
    } msg;
    
    struct zft_msg* zm = (struct zft_msg*)msg.msg;
    zm->iovcnt = 1;  // Single buffer receive

    // Process network events
    zf_reactor_perform(stack_);

    // Receive data (zero-copy)
    zft_zc_recv(zock_, zm, 0);
    if (zm->iovcnt == 0) 
      return false;  // No data available

    const uint8_t* new_data = (const uint8_t*)msg.iov.iov_base;
    uint32_t new_size = msg.iov.iov_len;

    // Handle connection close
    if (new_size == 0) {
      zft_zc_recv_done(zock_, zm);
      close("remote close");
      return false;
    }

    // Check buffer overflow
    if (new_size + tail_ > Conf::RecvBufSize) {
      zft_zc_recv_done(zock_, zm);
      close("recv buf full");
      return false;
    }

    // Process new data
    if (tail_ == 0) {
      // Directly process if no buffered data
      uint32_t remaining = handler(new_data, new_size);
      if (remaining) {
        // Save unprocessed data
        new_data += new_size - remaining;
        memcpy(recvbuf_, new_data, remaining);
        tail_ = remaining;
      }
    }
    else {
      // Append to existing buffered data
      memcpy(recvbuf_ + tail_, new_data, new_size);
      tail_ += new_size;
      
      // Process combined data
      uint32_t remaining = handler(recvbuf_ + head_, tail_ - head_);
      
      if (remaining == 0) {
        // All data processed
        head_ = tail_ = 0;
      }
      else {
        // Some data remains unprocessed
        head_ = tail_ - remaining;
        
        // Compact buffer if too much wasted space
        if (head_ >= Conf::RecvBufSize / 2) {
          memcpy(recvbuf_, recvbuf_ + head_, remaining);
          head_ = 0;
          tail_ = remaining;
        }
      }
    }
    
    // Release buffer (if connection still open)
    if (zock_) {
      zft_zc_recv_done(zock_, zm);
    }
    return true;
  }

  // Initializes connection state
  bool open(int64_t now, struct zft* zock, struct zf_stack* stack) {
    zock_ = zock;          // Store socket
    stack_ = stack;        // Store stack
    head_ = tail_ = 0;     // Reset buffer pointers
    send_ts_ = now;        // Set initial send timestamp
    expire_ts_ = now + Conf::RecvTimeoutSec;  // Set receive timeout
    return true;
  }

  // Saves error message with optional error code
  void saveError(const char* msg, int rc) {
    snprintf(last_error_, sizeof(last_error_), "%s %s", 
             msg, rc < 0 ? (const char*)strerror(-rc) : "");
  }

  // Member variables
  struct zft* zock_ = nullptr;        // ZeroFriction socket
  struct zf_stack* stack_ = nullptr;  // ZeroFriction stack
  
  // Timers
  int64_t send_ts_ = 0;      // Last send time
  int64_t expire_ts_ = 0;    // Receive expiration time
  
  // Receive buffer management
  uint32_t head_;             // Start of valid data in recvbuf_
  uint32_t tail_;             // End of valid data in recvbuf_
  uint8_t recvbuf_[Conf::RecvBufSize];  // Data buffer
  
  char last_error_[64] = "";  // Last error message
};

/* TCP Client class */
template<typename Conf>
class TcpdirectTcpClient : public TcpdirectTcpConnection<Conf>
{
public:
  using Conn = TcpdirectTcpConnection<Conf>;

  ~TcpdirectTcpClient() {
    this->close("destruct");
    if (this->stack_) {
      zf_stack_free(this->stack_);  // Free ZeroFriction stack
    }
  }

  // Initializes client with connection parameters
  bool init(const char* interface, const char* server_ip, 
            uint16_t server_port, uint16_t local_port = 0) {
    // Set up server address structure
    server_addr_.sin_family = AF_INET;
    inet_pton(AF_INET, server_ip, &(server_addr_.sin_addr));  // Convert IP
    server_addr_.sin_port = htons(server_port);  // Convert port
    bzero(&(server_addr_.sin_zero), 8);
    local_port_be_ = htons(local_port);  // Convert local port

    // Initialize ZeroFriction library
    int rc;
    if ((rc = _zf_init()) < 0) {
      this->saveError("zf_init error", rc);
      return false;
    }

    // Allocate attributes if not already done
    if (!attr_) {
      if ((rc = zf_attr_alloc(&attr_)) < 0) {
        this->saveError("zf_attr_alloc error", rc);
        return false;
      }
      // Configure interface and performance settings
      zf_attr_set_str(attr_, "interface", interface);
      zf_attr_set_int(attr_, "reactor_spin_count", 1);
    }

    // Allocate stack if not already done
    if (!this->stack_ && (rc = zf_stack_alloc(attr_, &this->stack_)) < 0) {
      this->saveError("zf_stack_alloc error", rc);
      zf_attr_free(attr_);
      attr_ = nullptr;
      return false;
    }
    return true;
  }

  // Allows reconnection attempts
  void allowReconnect() { next_conn_ts_ = 0; }

  // Polls for events and handles them via handler
  template<typename Handler>
  void poll(Handler& handler) {
    int64_t now = time(0);
    
    // Handle connection state
    if (!this->isConnected()) {
      // Check if we should attempt reconnect
      if (now < next_conn_ts_) return;
      
      // Set next reconnect time
      if (Conf::ConnRetrySec)
        next_conn_ts_ = now + Conf::ConnRetrySec;
      else
        next_conn_ts_ = std::numeric_limits<int64_t>::max(); // Disable reconnect
      
      // Attempt connection
      if (!this->connect(attr_, server_addr_, local_port_be_)) {
        handler.onTcpConnectFailed();
        return;
      }
      handler.onTcpConnected(*this);
    }
    
    // Poll connection for events
    this->pollConn(now, handler);
    
    // Handle disconnection
    if (!this->isConnected()) 
      handler.onTcpDisconnect(*this);
  }

private:
  struct zf_attr* attr_ = nullptr;      // ZeroFriction attributes
  int64_t next_conn_ts_ = 0;            // Next reconnect attempt time
  struct sockaddr_in server_addr_;      // Server address
  uint16_t local_port_be_;              // Local port in network byte order
};

/* TCP Server class */
template<typename Conf>
class TcpdirectTcpServer
{
public:
  using Conn = TcpdirectTcpConnection<Conf>;

  // Initializes server with listening parameters
  bool init(const char* interface, const char* server_ip, uint16_t server_port) {
    // Initialize connection pointers
    for (uint32_t i = 0; i < Conf::MaxConns; i++) 
      conns_[i] = conns_data_ + i;
    
    // Initialize ZeroFriction library
    int rc;
    if ((rc = _zf_init()) < 0) {
      saveError("zf_init error", rc);
      return false;
    }

    // Allocate and configure attributes
    struct zf_attr* attr;
    if ((rc = zf_attr_alloc(&attr)) < 0) {
      saveError("zf_attr_alloc error", rc);
      return false;
    }
    zf_attr_set_str(attr, "interface", interface);
    zf_attr_set_int(attr, "reactor_spin_count", 1);

    // Allocate stack
    if ((rc = zf_stack_alloc(attr, &stack_)) < 0) {
      saveError("zf_stack_alloc error", rc);
      zf_attr_free(attr);
      return false;
    }

    // Set up server address
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &(servaddr.sin_addr));

    // Start listening
    if ((rc = zftl_listen(stack_, (struct sockaddr*)&servaddr, 
                         sizeof(servaddr), attr, &listener_)) < 0) {
      saveError("zftl_listen error", rc);
      return false;
    }

    return true;
  }

  // Closes server with given reason
  void close(const char* reason) {
    if (listener_) {
      zftl_free(listener_);  // Free listener
      listener_ = nullptr;
      saveError(reason, 0);
    }
    if (stack_) {
      zf_stack_free(stack_);  // Free stack
      stack_ = nullptr;
    }
  }

  // Returns last error message
  const char* getLastError() { return last_error_; };

  ~TcpdirectTcpServer() { close("destruct"); }

  // Checks if server is closed
  bool isClosed() { return listener_ == nullptr; }

  // Gets current connection count
  uint32_t getConnCnt() { return conns_cnt_; }

  // Iterates over all active connections
  template<typename Handler>
  void foreachConn(Handler handler) {
    for (uint32_t i = 0; i < conns_cnt_; i++) {
      Conn& conn = *conns_[i];
      handler(conn);
    }
  }

  // Polls for server events and handles them
  template<typename Handler>
  void poll(Handler& handler) {
    int64_t now = time(0);
    
    // Accept new connections if we have room
    if (conns_cnt_ < Conf::MaxConns) {
      Conn& conn = *conns_[conns_cnt_];
      struct zft* zock;
      
      // Process network events
      zf_reactor_perform(stack_);
      
      // Accept new connection
      if (zftl_accept(listener_, &zock) >= 0) {
        conn.open(now, zock, stack_);
        conns_cnt_++;
        handler.onTcpConnected(conn);
      }
    }
    
    // Poll all active connections
    for (uint32_t i = 0; i < conns_cnt_;) {
      Conn& conn = *conns_[i];
      conn.pollConn(now, handler);
      
      if (conn.isConnected()) {
        i++;  // Move to next connection
      }
      else {
        // Remove disconnected connection
        std::swap(conns_[i], conns_[--conns_cnt_]);
        handler.onTcpDisconnect(conn);
      }
    }
  }

private:
  // Saves error message with optional error code
  void saveError(const char* msg, int rc) {
    snprintf(last_error_, sizeof(last_error_), "%s %s", 
             msg, rc < 0 ? (const char*)strerror(-rc) : "");
  }

  // Member variables
  struct zf_stack* stack_ = nullptr;  // ZeroFriction stack
  struct zftl* listener_ = nullptr;   // Listener socket
  uint32_t conns_cnt_ = 0;            // Active connection count
  Conn* conns_[Conf::MaxConns];       // Connection pointers
  Conn conns_data_[Conf::MaxConns];   // Connection objects
  char last_error_[64] = "";          // Last error message
};
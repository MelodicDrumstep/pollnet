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

#include <limits>
#include "TcpClient.h"
#include "TcpServer.h"

// Wrapper class for an EfviTcpClient (TCP client with custom configurations)
template<typename Conf>
class EfviTcpClient
{
  // Configuration structure for the client
  struct ClientConf
  {
    // Define static configuration values used for the connection
    static const uint32_t ConnSendBufCnt = 1024; // Send buffer count
    static const bool SendBuf1K = true; // Whether to use 1KB send buffers
    static const uint32_t ConnRecvBufSize = Conf::RecvBufSize; // Receive buffer size from configuration
    static const uint32_t MaxConnCnt = 1; // Maximum number of connections
    static const uint32_t MaxTimeWaitConnCnt = 1; // Maximum number of time-wait connections
    static const uint32_t RecvBufCnt = 512; // Receive buffer count
    static const uint32_t SynRetries = 3; // Number of retries for connection establishment
    static const uint32_t TcpRetries = 10; // Number of TCP retries
    static const uint32_t DelayedAckMS = 10; // Delayed acknowledgment time in milliseconds
    static const uint32_t MinRtoMS = 100; // Minimum retransmission timeout in milliseconds
    static const uint32_t MaxRtoMS = 30 * 1000; // Maximum retransmission timeout in milliseconds
    static const bool WindowScaleOption = false; // Window scaling option (disabled)
    static const bool TimestampOption = false; // Timestamp option (disabled)
    static const int CongestionControlAlgo = 0; // Congestion control algorithm (0 = none)
    static const uint32_t UserTimerCnt = 2; // Number of user timers
    struct UserData : public Conf::UserData
    {
      const char* err_ = nullptr; // Error message
    };
  };

  using TcpClient = efvitcp::TcpClient<ClientConf>;
  using TcpConn = typename TcpClient::Conn;

public:
  // Constructor: Initializes the EfviTcpClient object and establishes the connection
  EfviTcpClient()
    : conn(*(Conn*)&client.getConn()) {}

  // Connection structure, inheriting from TcpConn
  struct Conn : public TcpConn
  {
    // Check if the connection is established
    bool isConnected() { return this->isEstablished(); }

    // Retrieve the last error message
    const char* getLastError() { return this->err_; };

    // Close the connection with a reason
    void close(const char* reason) {
      this->err_ = reason;
      TcpConn::close();
    }

    // Write data to the connection (blocking)
    int writeSome(const void* data, uint32_t size, bool more = false) {
      int ret = this->send(data, size, more);
      if (Conf::SendTimeoutSec) this->setUserTimer(0, Conf::SendTimeoutSec * 1000);
      // If send timeout is enabled, statr the timer
      return ret;
    }

    // Write data to the connection (non-blocking)
    bool writeNonblock(const void* data, uint32_t size, bool more = false) {
      if ((uint32_t)writeSome(data, size, more) != size) {
        close("send buffer full");
        return false;
      }
      return true;
    }
  };

  // Retrieve the last error message from the connection
  const char* getLastError() { return conn.err_; };

  // Check if the connection is established
  bool isConnected() { return conn.isEstablished(); }

  // Initialize the client by setting interface, server IP, and server port
  bool init(const char* interface, const char* server_ip, uint16_t server_port,
            uint16_t local_port = 0) {
    if ((conn.err_ = client.init(interface))) return false;
    server_ip_ = server_ip;
    server_port_ = server_port;
    local_port_ = local_port;
    return true;
  }

  // Write some data to the connection
  int writeSome(const void* data, uint32_t size, bool more = false) { return conn.writeSome(data, size, more); }

  // Write data non-blocking to the connection
  bool writeNonblock(const void* data, uint32_t size, bool more = false) {
    return conn.writeNonblock(data, size, more);
  }

  // Close the connection with a reason
  void close(const char* reason) { conn.close(reason); }

  // Allow reconnection attempts if the connection fails
  void allowReconnect() { next_conn_ts_ = 0; }

  // Poll the client for events, passing a handler for processing the events
  template<typename Handler>
  void poll(Handler& handler, int64_t ns = 0) {
    if (conn.isClosed()) {
      int64_t now = time(0);
      if (now >= next_conn_ts_) {
        if (Conf::ConnRetrySec)
          next_conn_ts_ = now + Conf::ConnRetrySec;
        else
          next_conn_ts_ = std::numeric_limits<int64_t>::max(); // disable reconnect
        if ((conn.err_ = client.connect(server_ip_.c_str(), server_port_, local_port_))) {
          handler.onTcpConnectFailed();
        }
      }
    }

    // Temporary handler to handle TCP connection events
    struct TmpHandler
    {
      TmpHandler(Handler& h_, Conn& conn_)
        : handler(h_)
        , conn(conn_) {}

      void onConnectionRefused() {
        conn.err_ = "connection refused";
        handler.onTcpConnectFailed();
      }
      void onConnectionReset(TcpConn&) {
        conn.err_ = "connection reset";
        handler.onTcpDisconnect(conn);
      }
      void onConnectionTimeout(TcpConn&) {
        conn.err_ = "connection timeout";
        if (!conn.isEstablished()) handler.onTcpConnectFailed();
        else
          handler.onTcpDisconnect(conn);
      }
      void onConnectionClosed(TcpConn&) {
        conn.err_ = "connection closed";
        handler.onTcpDisconnect(conn);
      }
      void onFin(TcpConn&, uint8_t* data, uint32_t size) {
        if (size) handler.onTcpData(conn, data, size);
        conn.close("remote close");
        handler.onTcpDisconnect(conn);
      }
      void onMoreSendable(TcpConn&) {}
      void onUserTimeout(TcpConn&, uint32_t timer_id) {
        if (timer_id == 0)
          handler.onSendTimeout(conn);
        else
          handler.onRecvTimeout(conn);
      }
      void onConnectionEstablished(TcpConn&) {
        if (Conf::SendTimeoutSec) conn.setUserTimer(0, Conf::SendTimeoutSec * 1000);
        if (Conf::RecvTimeoutSec) conn.setUserTimer(1, Conf::RecvTimeoutSec * 1000);
        handler.onTcpConnected(conn);
      }
      uint32_t onData(TcpConn&, const uint8_t* data, uint32_t size) {
        if (Conf::RecvTimeoutSec) conn.setUserTimer(1, Conf::RecvTimeoutSec * 1000);
        return handler.onTcpData(conn, data, size);
      }

      Handler& handler;
      Conn& conn;
    } tmp_handler(handler, conn);

    // Perform polling for the client
    client.poll(tmp_handler, ns);
  }

  // Client instance used to handle the TCP connections
  TcpClient client;
  std::string server_ip_; // Server IP address
  uint16_t server_port_; // Server port
  uint16_t local_port_; // Local port for the connection
  Conn& conn; // Reference to the current connection
  int64_t next_conn_ts_ = 0; // Next connection retry timestamp
};

// Wrapper class for an EfviTcpServer (TCP server with custom configurations)
template<typename Conf>
class EfviTcpServer
{
  // Configuration structure for the server
  struct ServerConf
  {
    // Static configuration values for the server
    static const uint32_t ConnSendBufCnt = 1024; // Send buffer count
    static const bool SendBuf1K = true; // Whether to use 1KB send buffers
    static const uint32_t ConnRecvBufSize = Conf::RecvBufSize; // Receive buffer size from configuration
    static const uint32_t MaxConnCnt = Conf::MaxConns; // Max number of allowed connections
    static const uint32_t MaxTimeWaitConnCnt = Conf::MaxConns; // Max number of time-wait connections
    static const uint32_t RecvBufCnt = 512; // Receive buffer count
    static const uint32_t SynRetries = 3; // Number of retries for connection establishment
    static const uint32_t TcpRetries = 10; // Number of TCP retries
    static const uint32_t DelayedAckMS = 10; // Delayed acknowledgment time in milliseconds
    static const uint32_t MinRtoMS = 100; // Minimum retransmission timeout in milliseconds
    static const uint32_t MaxRtoMS = 30 * 1000; // Maximum retransmission timeout in milliseconds
    static const bool WindowScaleOption = false; // Window scaling option (disabled)
    static const bool TimestampOption = false; // Timestamp option (disabled)
    static const int CongestionControlAlgo = 0; // Congestion control algorithm (0 = none)
    static const uint32_t UserTimerCnt = 2; // Number of user timers
    struct UserData : public Conf::UserData
    {
      const char* err_ = nullptr; // Error message
    };
  };

  // Define aliases for TcpServer and TcpConn using ServerConf
  using TcpServer = efvitcp::TcpServer<ServerConf>;
  using TcpConn = typename TcpServer::Conn;

public:
  EfviTcpServer() {}

  // Connection structure, inheriting from TcpConn
  struct Conn : public TcpConn
  {
    // Check if the connection is established
    bool isConnected() { return this->isEstablished(); }

    // Retrieve the last error message
    const char* getLastError() { return this->err_; };

    // Close the connection with a reason
    void close(const char* reason) {
      this->err_ = reason;
      TcpConn::close();
    }

    // Write data to the connection (non-blocking)
    bool writeNonblock(const void* data, uint32_t size, bool more = false) {
      if (this->send(data, size, more) != size) {
        close("send buffer full");
        return false;
      }
      if (Conf::SendTimeoutSec) this->setUserTimer(0, Conf::SendTimeoutSec * 1000);
      return true;
    }
  };

  // Retrieve the last error message
  const char* getLastError() { return err_; };

  // Initialize the server by setting interface, server IP, and server port
  bool init(const char* interface, const char* server_ip, uint16_t server_port) {
    if ((err_ = server_.init(interface))) return false;
    if ((err_ = server_.listen(server_port))) return false;
    return true;
  }

  // Close the server with a reason
  void close(const char* reason) {
    if (reason) err_ = reason;
    server_.close();
  }

  // Check if the server is closed
  bool isClosed() { return err_; }

  // Get the current connection count
  uint32_t getConnCnt() { return server_.getConnCnt(); }

  // Iterate through each connection and apply a handler
  template<typename Handler>
  void foreachConn(Handler handler) {
    server_.foreachConn([&](TcpConn& conn) {
      handler(static_cast<Conn&>(conn));
    });
  }

  // Poll the server for events, passing a handler for processing the events
  template<typename Handler>
  void poll(Handler& handler) {
    server_.poll(handler);
  }

  // Server instance used to handle the TCP connections
  TcpServer server_;
  const char* err_ = nullptr; // Error message
};

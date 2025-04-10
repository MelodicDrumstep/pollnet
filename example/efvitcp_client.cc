#include <bits/stdc++.h>
using namespace std;
#include "../efvitcp/TcpClient.h"

// Configuration structure for TCP client parameters
struct Conf
{
  static const uint32_t ConnSendBufCnt = 128;      // Number of send buffers per connection
  static const bool SendBuf1K = true;              // Use 1KB send buffers if true
  static const uint32_t ConnRecvBufSize = 40960;   // Receive buffer size per connection (40KB)
  static const uint32_t MaxConnCnt = 2;            // Maximum concurrent connections
  static const uint32_t MaxTimeWaitConnCnt = 2;    // Max connections in TIME_WAIT state
  static const uint32_t RecvBufCnt = 128;          // Number of receive buffers
  static const uint32_t SynRetries = 3;            // SYN packet retry attempts
  static const uint32_t TcpRetries = 10;           // TCP packet retry attempts
  static const uint32_t DelayedAckMS = 10;         // Delayed ACK timeout in milliseconds
  static const uint32_t MinRtoMS = 100;            // Minimum retransmission timeout (ms)
  static const uint32_t MaxRtoMS = 30 * 1000;      // Maximum retransmission timeout (30s)
  static const bool WindowScaleOption = false;      // Disable TCP window scaling
  static const bool TimestampOption = false;        // Disable TCP timestamps
  static const int CongestionControlAlgo = 0;       // 0=none, 1=New Reno, 2=CUBIC
  static const uint32_t UserTimerCnt = 2;           // Number of user timers per connection
  
  // User-defined data attached to each connection
  struct UserData
  {
  };
};

// Type aliases for TCP client and connection
using TcpClient = efvitcp::TcpClient<Conf>;
using TcpConn = TcpClient::Conn;

// Get current timestamp in nanoseconds
inline int64_t getns() {
  timespec ts;
  ::clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// Network packet structure (packed to avoid alignment padding)
#pragma pack(push, 1)
struct Packet
{
  int64_t ts = 0;  // Timestamp when packet was sent
  int64_t val = 0; // Sequence value
};
#pragma pack(pop)

// Global flag for graceful shutdown
volatile bool running = true;

// Signal handler for CTRL+C and termination
void my_handler(int s) {
  running = false;
}

// TCP Client implementation class
class Client
{
public:
  // Initialize client with network interface and server details
  bool init(const char* interface, const char* server_ip, uint16_t server_port) {
    const char* err = client.init(interface);
    if (err) {
      cout << "Client init failed: " << err << endl;
      return false;
    }
    err = client.connect(server_ip, server_port);
    if (err) {
      cout << "Connection failed: " << err << endl;
      return false;
    }
    return true;
  }

  // Process network events
  void poll() { client.poll(*this); }

  // Gracefully close connection
  bool bye() {
    client.poll(*this);
    if (!conn_ || conn_->isClosed()) return true;
    conn_->sendFin(); // Initiate graceful shutdown
    return false;
  }

  // --- TCP Event Handlers ---

  // Called when server refuses connection
  void onConnectionRefused() { 
    cout << "Connection refused by server" << endl; 
  }

  // Called when TCP connection is established
  void onConnectionEstablished(TcpConn& conn) {
    conn_ = &conn; // Store active connection
    cout << "Connection established" << endl;
    cout << "Current send buffer space: " << conn.getSendable() << " bytes" << endl;
    
    // Set timers:
    // Timer 0: 10-second receive timeout
    // Timer 1: 1ms delay before first data transmission
    conn.setUserTimer(0, 10 * 1000);
    conn.setUserTimer(1, 1);
  }

  // Called when data is received
  uint32_t onData(TcpConn& conn, uint8_t* data, uint32_t size) {
    auto now = getns();
    // Process complete packets
    while (size >= sizeof(Packet)) {
      const Packet& recv_pack = *(const Packet*)data;
      auto lat = now - recv_pack.ts; // Calculate latency
      cout << "Received value: " << recv_pack.val 
           << " with latency: " << lat << " ns" << endl;
           
      // Validate sequence
      if (recv_pack.val != ++last_recv_val) {
        cout << "Sequence error! Received: " << recv_pack.val 
             << " Expected: " << last_recv_val << endl;
        exit(1);
      }
      data += sizeof(Packet);
      size -= sizeof(Packet);
    }
    // Reset receive timeout
    conn.setUserTimer(0, 10 * 1000);
    return size; // Return remaining unprocessed data size
  }

  // Called on connection reset (RST)
  void onConnectionReset(TcpConn& conn) { 
    cout << "Connection reset by peer" << endl; 
  }

  // Called when connection fully closes
  void onConnectionClosed(TcpConn& conn) { 
    cout << "Connection closed" << endl; 
  }

  // Called on FIN received
  void onFin(TcpConn& conn, uint8_t* data, uint32_t size) {
    cout << "FIN received with " << size << " bytes remaining" << endl;
    conn.sendFin(); // Respond with FIN
  }

  // Called on connection timeout
  void onConnectionTimeout(TcpConn& conn) {
    cout << "Connection timeout, established: " << conn.isEstablished() << endl;
  }

  // Called when more send buffer space becomes available
  void onMoreSendable(TcpConn& conn) {}

  // Called when user timer expires
  void onUserTimeout(TcpConn& conn, uint32_t timer_id) {
    if (timer_id == 0) { // Receive timeout
      cout << "Receive timeout for connection: " << conn.getConnId() << endl;
      conn.close();
    }
    else if (timer_id == 1) { // Send timer
      Packet packs[1];
      auto now = getns();

      // Check available send space
      if (conn.getSendable() >= sizeof(packs)) {
        // Prepare packet
        for (auto& pack : packs) {
          pack.val = ++last_send_val;
          pack.ts = now;
        }

        // Send packet
        if (conn.send(packs, sizeof(packs)) != sizeof(packs)) {
          cout << "Send failed! Available: " << conn.getSendable() << " bytes" << endl;
          exit(1);
        }
      }
      // Reschedule send timer for 1 second later
      conn.setUserTimer(1, 1000);
    }
    else {
      cout << "Invalid timer ID: " << timer_id 
           << " for connection: " << conn.getConnId() << endl;
      exit(1);
    }
  }

private:
  TcpClient client;        // TCP client instance
  TcpConn* conn_ = nullptr; // Active connection
  int64_t last_recv_val = 0; // Last received sequence number
  int64_t last_send_val = 0; // Last sent sequence number
};

// Number of parallel clients
const int NCli = 100;
Client clis[NCli]; // Array of client instances

int main(int argc, const char** argv) {
  // Set up signal handlers for graceful shutdown
  struct sigaction sigIntHandler;
  sigIntHandler.sa_handler = my_handler;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;
  sigaction(SIGINT, &sigIntHandler, NULL);
  sigaction(SIGTERM, &sigIntHandler, NULL);
  sigaction(SIGPIPE, &sigIntHandler, NULL);

  // Validate command line arguments
  if (argc < 4) {
    cout << "Usage: " << argv[0] << " interface server_ip server_port" << endl;
    return 1;
  }

  const char* interface = argv[1];
  const char* server_ip = argv[2];
  uint16_t server_port = atoi(argv[3]);

  // Initialize all clients
  for (Client& cli : clis) {
    if (!cli.init(interface, server_ip, server_port)) return 1;
  }

  // Main event loop
  while (running) {
    for (int i = 0; i < NCli; i++) {
      clis[i].poll(); // Process events for each client
    }
  }

  // Graceful shutdown sequence
  cout << "Shutting down..." << endl;
  bool all_ended = false;
  while (!all_ended) {
    all_ended = true;
    for (Client& cli : clis) {
      if (!cli.bye()) all_ended = false;
    }
  }
  return 0;
}
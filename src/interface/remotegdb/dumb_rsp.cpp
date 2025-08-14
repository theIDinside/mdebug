// rsp_nostop.cpp
// Minimal GDB RSP client that negotiates non-stop mode and gets ready to resume.
//
// NOTE: This is a barebones example intended for clarity. It handles happy paths,
//       core negotiation, and a few common responses. Extend for production use:
//       timeouts, retries, escaped binary, multi-packet reads, qXfer, etc.

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

static std::string
hex2(uint8_t v)
{
  static const char *d = "0123456789abcdef";
  std::string s(2, '0');
  s[0] = d[(v >> 4) & 0xF];
  s[1] = d[v & 0xF];
  return s;
}
static int
hexval(char c)
{
  if ('0' <= c && c <= '9') {
    return c - '0';
  }
  if ('a' <= c && c <= 'f') {
    return 10 + (c - 'a');
  }
  if ('A' <= c && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

class Rsp
{
public:
  explicit Rsp(std::string host, std::string port) : host_(std::move(host)), port_(std::move(port)) {}

  void
  connect_or_die()
  {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res;
    int rc = getaddrinfo(host_.c_str(), port_.c_str(), &hints, &res);
    if (rc != 0) {
      die(std::string("getaddrinfo: ") + gai_strerror(rc));
    }
    int sock = -1;
    for (auto *p = res; p; p = p->ai_next) {
      sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (sock < 0) {
        continue;
      }
      if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
        fd_ = sock;
        break;
      }
      ::close(sock);
      sock = -1;
    }
    freeaddrinfo(res);
    if (fd_ < 0) {
      die("connect failed");
    }
    // No data from gdbserver is guaranteed until we query "?"; some targets might
    // emit a stop reply spontaneously but don't rely on it.
  }

  // High-level steps
  void
  negotiate()
  {
    std::cout << "[*] qSupported…\n";
    auto supp = transact("qSupported");
    parseSupported(supp);

    if (!no_ack_mode_) {
      if (supported_.count("QStartNoAckMode")) {
        std::cout << "[*] Entering no-ack mode…\n";
        auto r = transact("QStartNoAckMode");
        if (r == "OK") {
          no_ack_mode_ = true; /* after OK, neither side sends +/- */
        }
      }
    }

    if (supported_.count("QNonStop")) {
      std::cout << "[*] Enabling non-stop…\n";
      auto r = transact("QNonStop:1");
      if (r != "OK") {
        die("QNonStop:1 rejected: " + r);
      }
    } else {
      die("Target does not advertise QNonStop");
    }

    // vCont capabilities
    std::cout << "[*] Query vCont…\n";
    auto v = transact("vCont?");
    // Example: "vCont;c;s;t;r"
    vcont_actions_ = parseVCont(v);
    if (!vcont_actions_.count('c')) {
      die("Target lacks vCont;c");
    }
    if (!vcont_actions_.count('t')) {
      std::cerr << "[!] Target lacks vCont;t (thread suspend)\n";
    }

    // Optional but useful: thread create/exit events
    if (supported_.count("QThreadEvents")) {
      std::cout << "[*] Enabling thread events…\n";
      auto r = transact("QThreadEvents:1");
      if (r != "OK") {
        std::cerr << "[!] QThreadEvents:1 rejected: " << r << "\n";
      }
    }

    // Good practice: select "any" thread for control / general registers context.
    // Hc sets the "current" thread for control ops; Hg for general regs.
    // -1 means "any".
    std::cout << "[*] Selecting any thread (Hc-1 / Hg-1)…\n";
    if (transact("Hc-1").rfind("OK", 0) != 0) {
      std::cerr << "[!] Hc-1 not OK\n";
    }
    if (transact("Hg-1").rfind("OK", 0) != 0) {
      std::cerr << "[!] Hg-1 not OK\n";
    }
  }

  // Ask remote for initial stop reason (mandatory first query).
  std::string
  initial_stop_reason()
  {
    std::cout << "[*] Query initial stop reason (?)…\n";
    auto r = transact("?");
    // Expect "Sxx" or "T..." in non-stop mode too; keep it for UI.
    std::cout << "    -> " << r << "\n";
    return r;
  }

  // Enumerate threads via qfThreadInfo/qsThreadInfo; returns list of tids (hex).
  std::vector<std::string>
  list_threads()
  {
    std::vector<std::string> tids;
    std::string pkt = "qfThreadInfo";
    for (;;) {
      auto resp = transact(pkt);
      if (resp == "l") {
        break; // end
      }
      if (resp == "m") {
        pkt = "qsThreadInfo";
        continue;
      } // more
      if (resp.size() && resp[0] == 'm') {
        // m<pid_tid>,<pid_tid>,...
        parseCsvIds(resp.substr(1), tids);
        pkt = "qsThreadInfo";
      } else {
        std::cerr << "[!] Unexpected thread list chunk: " << resp << "\n";
        break;
      }
    }
    std::cout << "[*] Threads: ";
    for (auto &t : tids) {
      std::cout << t << " ";
    }
    std::cout << "\n";
    return tids;
  }

  // At this point you can resume: e.g. continue all or a specific thread.
  // We DO NOT actually resume here; leaving that to the embedding debugger.
  // Example calls you can make afterwards:
  //   sendPacket("vCont;c");                        // continue all
  //   sendPacket(("vCont;c:" + tid).c_str());       // continue one thread
  // For a "pause", sendInterrupt();                 // 0x03

  // Low-level helpers you may expose:

  std::string
  transact(const std::string &payload)
  {
    sendPacket(payload);
    return recvPacketPayload();
  }
  void
  sendInterrupt()
  { // pause-all in both modes
    uint8_t byte = 0x03;
    if (::send(fd_, &byte, 1, 0) != 1) {
      die("send interrupt failed");
    }
  }

  void
  close()
  {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = -1;
  }

  ~Rsp() { close(); }

private:
  std::string host_, port_;
  int fd_ = -1;
  bool no_ack_mode_ = false;
  std::set<std::string> supported_;
  std::set<char> vcont_actions_;

  [[noreturn]] void
  die(const std::string &msg)
  {
    std::cerr << "FATAL: " << msg << " (errno=" << errno << " " << std::strerror(errno) << ")\n";
    std::exit(2);
  }

  uint8_t
  checksum(const std::string &s)
  {
    uint32_t sum = 0;
    for (unsigned char c : s) {
      sum = (sum + c) & 0xFF;
    }
    return (uint8_t)sum;
  }

  void
  sendPacket(const std::string &payload)
  {
    std::string pkt;
    pkt.reserve(4 + payload.size());
    pkt.push_back('$');
    pkt += payload;
    pkt.push_back('#');
    pkt += hex2(checksum(payload));

    // Send
    size_t off = 0;
    while (off < pkt.size()) {
      ssize_t n = ::send(fd_, pkt.data() + off, pkt.size() - off, 0);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        die("send failed");
      }
      off += (size_t)n;
    }

    // ACK unless in no-ack mode
    if (!no_ack_mode_) {
      char ch;
      if (recvAll(&ch, 1) != 1) {
        die("no ack from target");
      }
      if (ch != '+') {
        if (ch == '-') {
          // retransmit once
          off = 0;
          while (off < pkt.size()) {
            ssize_t n = ::send(fd_, pkt.data() + off, pkt.size() - off, 0);
            if (n < 0) {
              if (errno == EINTR) {
                continue;
              }
              die("resend failed");
            }
            off += (size_t)n;
          }
          if (recvAll(&ch, 1) != 1 || ch != '+') {
            die("no ack after retransmit");
          }
        } else {
          die(std::string("unexpected ack byte: ") + ch);
        }
      }
    }
  }

  // Receives a single RSP packet and returns its payload (without $/#cc).
  // Handles incoming '+' acks if target still in ack mode; sends '+' to acknowledge packets.
  std::string
  recvPacketPayload()
  {
    // Read until '$'
    char ch;
    for (;;) {
      if (recvAll(&ch, 1) != 1) {
        die("recv failed");
      }
      if (ch == '$') {
        break;
      }
      // Some targets may send stray '+' acks; ignore.
    }

    // Read payload until '#'
    std::string payload;
    for (;;) {
      if (recvAll(&ch, 1) != 1) {
        die("recv failed");
      }
      if (ch == '#') {
        break;
      }
      payload.push_back(ch);
    }

    // Read checksum
    char c1, c2;
    if (recvAll(&c1, 1) != 1 || recvAll(&c2, 1) != 1) {
      die("recv checksum failed");
    }
    int hi = hexval(c1), lo = hexval(c2);
    if (hi < 0 || lo < 0) {
      die("bad checksum hex");
    }
    uint8_t want = (uint8_t)((hi << 4) | lo);
    uint8_t got = checksum(payload);
    if (got != want) {
      // NAK and retry read (very basic)
      if (!no_ack_mode_) {
        sendRaw("-");
      }
      // Discard and try again (recursive simple retry)
      return recvPacketPayload();
    } else {
      if (!no_ack_mode_) {
        sendRaw("+");
      }
    }

    return payload;
  }

  ssize_t
  recvAll(void *buf, size_t len)
  {
    uint8_t *p = static_cast<uint8_t *>(buf);
    size_t off = 0;
    while (off < len) {
      ssize_t n = ::recv(fd_, p + off, len - off, 0);
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        return n;
      }
      if (n == 0) {
        return 0; // EOF
      }
      off += (size_t)n;
    }
    return (ssize_t)off;
  }

  void
  sendRaw(const char *s, size_t n)
  {
    size_t off = 0;
    while (off < n) {
      ssize_t m = ::send(fd_, s + off, n - off, 0);
      if (m < 0) {
        if (errno == EINTR) {
          continue;
        }
        die("sendRaw failed");
      }
      off += (size_t)m;
    }
  }
  void
  sendRaw(const std::string &s)
  {
    sendRaw(s.data(), s.size());
  }
  void
  sendRaw(const char c)
  {
    sendRaw(&c, 1);
  }

  void
  parseSupported(const std::string &resp)
  {
    // Format: "PacketSize=...,QNonStop+,QStartNoAckMode+,qXfer:...;vContSupported+;..."
    std::stringstream ss(resp);
    std::string item;
    while (std::getline(ss, item, ';')) {
      auto plus = item.find('+');
      auto eq = item.find('=');
      if (plus != std::string::npos) {
        supported_.insert(item.substr(0, plus));
      } else if (eq != std::string::npos) {
        supported_.insert(item.substr(0, eq));
      } else if (!item.empty()) {
        supported_.insert(item);
      }
    }
    // Some servers advertise vContSupported in qSupported; some only answer vCont?.
    // We'll still query vCont? explicitly later.
  }

  static std::set<char>
  parseVCont(const std::string &v)
  {
    // Example: "vCont;c;s;C;S;t;r"
    std::set<char> acts;
    if (v.rfind("vCont", 0) != 0) {
      return acts;
    }
    size_t i = 5; // after "vCont"
    if (i < v.size() && v[i] == ';') {
      ++i;
    }
    while (i < v.size()) {
      char c = v[i];
      if (c == ';' || c == ':') {
        ++i;
        continue;
      }
      // actions are one letter: c/s/t/r/C/S etc.
      if (std::isalpha((unsigned char)c)) {
        acts.insert(c);
      }
      // skip to next ';'
      auto next = v.find(';', i);
      if (next == std::string::npos) {
        break;
      }
      i = next + 1;
    }
    return acts;
  }

  static void
  parseCsvIds(const std::string &csv, std::vector<std::string> &out)
  {
    std::stringstream ss(csv);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
      if (!tok.empty()) {
        out.push_back(tok);
      }
    }
  }
};

int
main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <host> <port>\n";
    std::cerr << "Example: " << argv[0] << " 127.0.0.1 1234\n";
    return 1;
  }

  std::string host = argv[1], port = argv[2];
  Rsp rsp(host, port);
  rsp.connect_or_die();

  // 1) Negotiate capabilities, switch to no-ack + non-stop, enable useful bits.
  rsp.negotiate();

  // 2) Get initial stop reason (mandatory first query in RSP sessions).
  auto stop = rsp.initial_stop_reason();

  // 3) Enumerate threads (optional but typically done before first resume).
  auto tids = rsp.list_threads();

  std::cout << "\n=== Ready to start debug session ===\n";
  std::cout << "You can now resume, e.g.:\n";
  std::cout << "  - Continue all:     send 'vCont;c'\n";
  if (!tids.empty()) {
    std::cout << "  - Continue TID " << tids.front() << ": send 'vCont;c:" << tids.front() << "'\n";
  }
  std::cout << "Or pause later by sending a single 0x03 byte (Ctrl-C) on the connection.\n\n";

  // This sample exits here; a real debugger would now enter an event loop
  // to read stop replies (T...), console (O...), thread events, etc.

  return 0;
}

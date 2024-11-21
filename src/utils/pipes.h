#pragma once
#include "common.h"
#include "utils/enumerator.h"
#include "utils/logger.h"
#include "utils/macros.h"
#include <cstring>
#include <fcntl.h>
#include <list>
#include <mutex>
#include <optional>
#include <sys/poll.h>

namespace utils {

template <typename Payload> class SynchronizedSignalPipe
{
  std::mutex payload_guard{};
  std::list<Payload> payload{};

  int read_fd{-1};
  int write_fd{-1};
  pollfd pollcfg;

  SynchronizedSignalPipe(int read, int write) noexcept
      : read_fd(read), write_fd(write), pollcfg{.fd = read_fd, .events = POLLIN, .revents = 0}
  {
  }

  bool
  notify() const noexcept
  {
    if (const auto res = ::write(write_fd, "+", 1); res == -1) {
      DLOG(logging::Channel::core, "Failed to notify on fd {}: {}", write_fd, strerror(errno));
      return false;
    }
    return true;
  }

public:
  NO_COPY(SynchronizedSignalPipe);

  ~SynchronizedSignalPipe() noexcept
  {
    if (read_fd != -1 || write_fd != -1) {
      close();
    }
  }

  SynchronizedSignalPipe(SynchronizedSignalPipe &&move) noexcept
      : read_fd(move.read_fd), write_fd(move.write_fd), pollcfg(move.pollcfg)
  {
    std::lock_guard lock(move.payload_guard);
    payload = std::move(move.payload);
    move.write_fd = -1;
    move.read_fd = -1;
  }

  SynchronizedSignalPipe &
  operator=(SynchronizedSignalPipe &&rhs) noexcept
  {
    if (this == &rhs) {
      return *this;
    }
    std::lock_guard lock(rhs.payload_guard);
    payload = std::move(rhs.payload);
    read_fd = rhs.read_fd;
    write_fd = rhs.write_fd;
    rhs.read_fd = -1;
    rhs.write_fd = -1;
    return *this;
  }

  pollfd
  get_config() const noexcept
  {
    return pollcfg;
  }
  int
  get_read() const noexcept
  {
    return read_fd;
  }
  int
  get_write() const noexcept
  {
    return write_fd;
  }

  void
  close() noexcept
  {
    ::close(read_fd);
    ::close(write_fd);
    read_fd = -1;
    write_fd = -1;
  }

  static SynchronizedSignalPipe<Payload>
  create() noexcept
  {
    int notify_pipe[2];
    VERIFY(pipe(notify_pipe) != -1, "Failed to set up notifier pipe {}", strerror(errno));
    auto flags = fcntl(notify_pipe[0], F_GETFL);
    VERIFY(flags != -1, "Failed to get flags for read-end of pipe");
    VERIFY(-1 != fcntl(notify_pipe[0], F_SETFL, flags | O_NONBLOCK), "Failed to set non-blocking for pipe");

    return SynchronizedSignalPipe<Payload>{notify_pipe[0], notify_pipe[1]};
  }

  bool
  poll(int timeout) noexcept
  {
    std::lock_guard l(payload_guard);
    if (!payload.empty()) {
      return true;
    }
    auto cnt = ::poll(&pollcfg, 1, timeout);
    if (cnt < 0) {
      DLOG(logging::Channel::core, "Failed to poll file descriptor: {}: {}", pollcfg.fd, strerror(errno));
    }
    return cnt > 0;
  }

  bool
  send(Payload &&p) noexcept
  {
    std::lock_guard l(payload_guard);
    payload.emplace_back(std::move(p));
    return notify();
  }
};

template <> class SynchronizedSignalPipe<void>
{
  int read_fd{-1};
  int write_fd{-1};
  pollfd pollcfg;

  SynchronizedSignalPipe(int read, int write) noexcept
      : read_fd(read), write_fd(write), pollcfg{.fd = read_fd, .events = POLLIN, .revents = 0}
  {
  }

  bool
  notify() const noexcept
  {
    if (const auto res = ::write(write_fd, "+", 1); res == -1) {
      DLOG(logging::Channel::core, "Failed to notify on fd {}: {}", write_fd, strerror(errno));
      return false;
    }
    return true;
  }

public:
  NO_COPY(SynchronizedSignalPipe);

  ~SynchronizedSignalPipe() noexcept
  {
    if (read_fd != -1 || write_fd != -1) {
      close();
    }
  }

  void
  close() noexcept
  {
    ::close(read_fd);
    ::close(write_fd);
    read_fd = -1;
    write_fd = -1;
  }

  pollfd
  get_config() const noexcept
  {
    return pollcfg;
  }
  int
  get_read() const noexcept
  {
    return read_fd;
  }
  int
  get_write() const noexcept
  {
    return write_fd;
  }
};

template <typename... Args>
static pollfd
get_config(const std::variant<SynchronizedSignalPipe<Args>...> &var) noexcept
{
  return std::visit([](const auto &v) -> pollfd { return v.get_config(); }, var);
}

struct PollResult
{
private:
  std::vector<u32> ready;

public:
  PollResult() noexcept = default;
  explicit PollResult(u32 count) noexcept : ready{} { ready.reserve(count); }

  void
  add(u32 index) noexcept
  {
    ready.push_back(index);
  }

  bool
  timed_out() const noexcept
  {
    return ready.empty();
  }

  std::optional<u32>
  next() noexcept
  {
    if (ready.empty()) {
      return {};
    }

    auto v = ready.back();
    ready.pop_back();
    return v;
  }
};

template <typename... Args> class SignalPipes
{
  static constexpr size_t PipesCount = sizeof...(Args);

  std::tuple<SynchronizedSignalPipe<Args>...> pipes;
  std::array<pollfd, PipesCount> poll_configurations{};

  void
  clear_revents() noexcept
  {
    for (auto &cfg : poll_configurations) {
      cfg.revents = 0;
    }
  }

public:
  constexpr SignalPipes(SynchronizedSignalPipe<Args>... add_pipes) noexcept : pipes(std::move(add_pipes)...)
  {
    poll_configurations = std::array<pollfd, PipesCount>{add_pipes.get_config()...};
  }

  PollResult
  poll(int timeout)
  {
    const auto res = ::poll(poll_configurations.data(), poll_configurations.size(), timeout);
    if (res == -1) {
      DLOG(logging::Channel::core, "Failed to call syscall poll: {}", strerror(errno));
    }

    if (res == 0) {
      return PollResult{};
    }
    PollResult result{res};

    for (auto [i, cfg] : utils::EnumerateView{poll_configurations}) {
      if (cfg.revents != 0) {
        result.add(i);
        cfg.revents = 0;
      }
    }
    return result;
  }
};

static constexpr auto
CreateSignalPipes(auto &&...ps) noexcept
{
  return SignalPipes{ps...};
}

} // namespace utils

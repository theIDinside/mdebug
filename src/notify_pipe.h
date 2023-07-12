#pragma once
#include "common.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <utility>

struct pollfd;

// clang-format off
template <typename E>
concept EnumType = std::is_enum<E>::value && requires(E e) {
  { std::to_underlying(e) } -> std::convertible_to<std::size_t>;
};
// clang-format on

namespace utils {
struct Notifier
{
  struct ReadEnd
  {
    int fd;
    operator int() noexcept { return fd; }

    [[maybe_unused]] constexpr bool
    consume_expected() noexcept
    {
      char ch;
      [[maybe_unused]] const auto res = ::read(fd, &ch, 1);
      ASSERT(res != -1, "Failed to consume posted event token due to error {}", strerror(errno));
      return true;
    }
  };

  struct WriteEnd
  {
    int fd;
    constexpr bool
    notify() const noexcept
    {
      return ::write(fd, "+", 1) > 0;
    }
  };

  static Notifier
  notify_pipe() noexcept
  {
    int notify_pipe[2];
    ASSERT(pipe(notify_pipe) != -1, "Failed to set up notifier pipe {}", strerror(errno));
    auto flags = fcntl(notify_pipe[0], F_GETFL);
    VERIFY(flags != -1, "Failed to get flags for read-end of pipe");
    VERIFY(-1 != fcntl(notify_pipe[0], F_SETFL, flags | O_NONBLOCK), "Failed to set non-blocking for pipe");
    return Notifier{.read = ReadEnd{notify_pipe[0]}, .write = WriteEnd{notify_pipe[1]}};
  }

  ReadEnd read;
  WriteEnd write;
};

template <size_t Size> struct NotifyManager
{
  std::array<Notifier::ReadEnd, Size> notifiers;
  std::array<std::string_view, Size> notifier_names;
  pollfd pollfds[Size];
  constexpr NotifyManager(std::array<Notifier::ReadEnd, Size> read_end_notifiers,
                          std::array<std::string_view, Size> names) noexcept
      : notifiers(read_end_notifiers), notifier_names(names)
  {
    for (auto i = Size - Size; i < Size; i++) {
      pollfds[i] = {.fd = notifiers[i].fd, .events = EPOLLIN, .revents = 0};
    }
  }

  bool
  poll(int timeout) noexcept
  {
    auto ready = ::poll(pollfds, Size, timeout);
    return ready > 0;
  }

  template <size_t Idx>
  constexpr bool
  has_notification() noexcept
  {
    const auto ok = (pollfds[Idx].revents & POLLIN) == POLLIN;
    if (ok) {
      char c;
      auto res = ::read(pollfds[Idx].fd, &c, 1);
      ASSERT(res != -1 && errno != EAGAIN, "Attempting to read from pipe when it would block");
    }
    pollfds[Idx].revents = 0;
    pollfds[Idx].events = POLLIN;
    pollfds[Idx].fd = notifiers[Idx].fd;
    return ok;
  }
};
}; // namespace utils
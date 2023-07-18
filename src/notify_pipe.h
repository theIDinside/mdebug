#pragma once
#include "common.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

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

    [[maybe_unused]] bool consume_expected() noexcept;
  };

  struct WriteEnd
  {
    int fd;
    bool notify() const noexcept;
  };
  static Notifier notify_pipe() noexcept;
  ReadEnd read;
  WriteEnd write;
};

struct AwaiterNotifier
{
  Notifier::ReadEnd notifier;
};

struct NotifyResult
{
  Tid pid;
};

struct NotifyManager
{
  // notifiers[0] & pollfds[0] __MUST__ be exclusive for IO Thread notifications.
  std::vector<Notifier::ReadEnd> notifiers;
  std::vector<std::string> notifier_names;
  std::vector<pollfd> pollfds;
  std::unordered_map<int, Tid> fd_to_target;
  NotifyManager(Notifier::ReadEnd io_read) noexcept;

  void add_notifier(Notifier::ReadEnd notifier, std::string name, Tid task_leader) noexcept;
  bool poll(int timeout) noexcept;
  bool has_io_ready() noexcept;
  void has_wait_ready(std::vector<NotifyResult> &result);
};
}; // namespace utils
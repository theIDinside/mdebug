#include "notify_pipe.h"

struct pollfd;

namespace utils {

/*static*/ Notifier
Notifier::notify_pipe() noexcept
{
  int notify_pipe[2];
  ASSERT(pipe(notify_pipe) != -1, "Failed to set up notifier pipe {}", strerror(errno));
  auto flags = fcntl(notify_pipe[0], F_GETFL);
  VERIFY(flags != -1, "Failed to get flags for read-end of pipe");
  VERIFY(-1 != fcntl(notify_pipe[0], F_SETFL, flags | O_NONBLOCK), "Failed to set non-blocking for pipe");
  return Notifier{.read = ReadEnd{notify_pipe[0]}, .write = WriteEnd{notify_pipe[1]}};
}

NotifyManager::NotifyManager(Notifier::ReadEnd io_read) noexcept : notifiers(), notifier_names(), fd_to_target()
{
  notifier_names.push_back("IO Thread");
  notifiers.push_back(io_read);
  pollfds.push_back({.fd = io_read.fd, .events = EPOLLIN, .revents = 0});
}

void
NotifyManager::add_notifier(Notifier::ReadEnd notifier, std::string name, Tid task_leader) noexcept
{
  notifiers.push_back(notifier);
  notifier_names.push_back(name);
  pollfds.push_back({.fd = notifier.fd, .events = EPOLLIN, .revents = 0});
  fd_to_target[notifier.fd] = task_leader;
}

bool
NotifyManager::poll(int timeout) noexcept
{
  auto ready = ::poll(pollfds.data(), pollfds.size(), timeout);
  return ready > 0;
}

bool
NotifyManager::has_io_ready() noexcept
{
  const auto ok = (pollfds[0].revents & POLLIN) == POLLIN;
  if (ok) {
    char c;
    auto res = ::read(pollfds[0].fd, &c, 1);
    ASSERT(res != -1 && errno != EAGAIN, "Attempting to read from pipe when it would block");
  }
  pollfds[0].revents = 0;
  pollfds[0].events = POLLIN;
  pollfds[0].fd = notifiers[0].fd;
  return ok;
}

void
NotifyManager::has_wait_ready(std::vector<NotifyResult> &result)
{
  result.clear();
  for (auto i = 1ul; i < pollfds.size(); i++) {
    const auto ok = (pollfds[i].revents & POLLIN) == POLLIN;
    if (ok) {
      result.push_back(NotifyResult{.pid = fd_to_target[pollfds[i].fd]});
      char c;
      auto res = ::read(pollfds[i].fd, &c, 1);
      ASSERT(res != -1 && errno != EAGAIN, "Attempting to read from pipe when it would block");
    }
    pollfds[i].revents = 0;
    pollfds[i].events = POLLIN;
  }
}
} // namespace utils
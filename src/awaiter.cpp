/** LICENSE TEMPLATE */
#include "awaiter.h"
#include "event_queue.h"
#include "utils/debugger_thread.h"
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <tracer.h>
namespace mdb {
static void
SignalFileDescriptorWork(std::stop_token &stopToken) noexcept
{
  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    perror("sigprocmask");
    return;
  }

  // Create signalfd for SIGCHLD

  // ScopedFd panics if fd == -1 (error value).
  // So we don't need error checking here. This is a hard error, we don't even try here.
  mdb::ScopedFd sfd = signalfd(-1, &mask, 0);
  mdb::ScopedFd epollFileDescriptor = epoll_create1(0);

  // Add the signalfd to the epoll instance
  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = sfd;
  if (epoll_ctl(epollFileDescriptor, EPOLL_CTL_ADD, sfd, &ev) == -1) {
    PANIC("epoll_ctl failed");
    return;
  }

  while (!stopToken.stop_requested()) {
    epoll_event events[1];
    int nfds = epoll_wait(epollFileDescriptor, events, std::size(events), -1);
    if (nfds == -1) {
      if (errno == EINTR) {
        continue;
      }
      PANIC("Failed to epoll wait");
    }
    for (int i = 0; i < nfds; ++i) {
      if (events[i].data.fd == sfd) {
        struct signalfd_siginfo fdsi;
        ssize_t bytes_read = read(sfd, &fdsi, sizeof(fdsi));
        if (bytes_read != sizeof(fdsi)) {
          PANIC("read from signalfd");
          continue;
        }

        if (fdsi.ssi_signo == SIGCHLD) {
          // Handle SIGCHLD: reap child processes
          std::array<WaitResult, 128> waitResult{};
          u32 count = 0;
          while (true) {
            int status;
            pid_t res = waitpid(-1, &status, WNOHANG | __WALL);
            if (res <= 0) {
              break;
            }
            waitResult[count].pid = res;
            waitResult[count].stat = status;
            count++;
            if (count >= std::size(waitResult)) {
              break;
            }
          }

          if (count == std::size(waitResult)) {
            DBGLOG(warning, "read the max number of wait events; potential stall can happen here.");
          }
          if (count > 0) {
            EventSystem::Get().PushReapedWaitResults(std::span{waitResult.data(), count});
          }
        }
      }
    }
  }
}

void
WaitStatusReaderThread::Start() noexcept
{
  mThread = DebuggerThread::SpawnDebuggerThread(
    "WaitStatReader", [this](std::stop_token &token) { SignalFileDescriptorWork(token); });
}

/* static */
std::unique_ptr<WaitStatusReaderThread>
WaitStatusReaderThread::Init() noexcept
{
  // Block SIGCHLD in this thread to handle it only via signalfd
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
    PANIC("sigprocmask failed");
  }
  return std::unique_ptr<WaitStatusReaderThread>{new WaitStatusReaderThread{}};
}
} // namespace mdb
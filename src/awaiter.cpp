#include "awaiter.h"
#include "event_queue.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include <sys/wait.h>

AwaiterThread::AwaiterThread(Tid task_leader) noexcept
    : thread(), keep_going(true), process_group_id(task_leader) {};

AwaiterThread::~AwaiterThread() noexcept
{
  keep_going = false;
  if (thread.joinable()) {
    thread.join();
  }
}

void
AwaiterThread::start_awaiter_thread(tc::TraceeCommandInterface *tc) noexcept
{
  thread = std::thread{[pid = tc->TaskLeaderTid(), &keep_going = keep_going]() {
    int error_tries = 0;
    const auto pgid = -(pid);
    while (keep_going) {
      int status = 0;
      const auto res = waitpid(pgid, &status, 0 | __WALL);
      if (res == -1) {
        error_tries++;
        if (!keep_going) {
          break;
        }
        VERIFY(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
        continue;
      }
      EventSystem::Get().PushWaitResult(WaitResult{.pid = res, .stat = status});
    }
    DBGLOG(core, "Exiting awaiter thread {}", pid);
  }};
}

void
AwaiterThread::init_shutdown() noexcept
{
  keep_going = false;
}
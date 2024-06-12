#include "awaiter.h"
#include "common.h"
#include "event_queue.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "supervisor.h"
#include <bits/chrono.h>
#include <bits/types/idtype_t.h>
#include <chrono>
#include <sys/wait.h>

AwaiterThread::AwaiterThread(Tid task_leader) noexcept
    : thread(), keep_going(true), process_group_id(task_leader){};

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
  thread = std::thread{[pid = tc->task_leader(), &keep_going = keep_going]() {
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
      const auto wait_result = process_status(res, status);
      push_wait_event(0, wait_result);
    }
    DBGLOG(core, "Exiting awaiter thread {}", pid);
  }};
}

void
AwaiterThread::init_shutdown() noexcept
{
  keep_going = false;
}
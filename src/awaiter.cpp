#include "awaiter.h"
#include "common.h"
#include "tracer.h"
#include <bits/chrono.h>
#include <chrono>
#include <sys/wait.h>

AwaiterThread::AwaiterThread(Notify notifier, Tid task_leader) noexcept
    : notifier(notifier), events_reaped(true), m{}, cv{}, initialized(false), thread(), should_cont(true),
      process_group_id(task_leader){};

AwaiterThread::~AwaiterThread() noexcept
{
  should_cont = false;
  reaped_events();
  thread.join();
}

void
AwaiterThread::reaped_events() noexcept
{
  events_reaped = true;
  cv.notify_one();
}

void
AwaiterThread::start_awaiter_thread() noexcept
{
  thread = std::thread{
      [&n = this->notifier, t = process_group_id, &cv = cv, &m = m, &ready = events_reaped, &c = should_cont]() {
        int error_tries = 0;
        while (c) {
          siginfo_t info_ptr;
          auto res = waitid(P_ALL, t, &info_ptr, WEXITED | WSTOPPED | WNOWAIT);
          if (res == -1) {
            error_tries++;
            VERIFY(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
            continue;
          }
          error_tries = 0;
          // notify Tracer thread that it can pull out wait status info
          n.notify();
          {
            std::unique_lock lk(m);
            ready = false;
            while (!ready && c)
              cv.wait(lk);
          }
          ready = false;
        }
      }};
}

void
AwaiterThread::set_process_exited() noexcept
{
  should_cont = false;
}

Notify
AwaiterThread::get_notifier() noexcept
{
  return notifier;
}
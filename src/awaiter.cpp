#include "awaiter.h"
#include <sys/wait.h>

void
awaiter_thread_job(Notify &notifier, Tid task_leader, std::condition_variable &cv, std::mutex &m, bool &ready)
{
  int error_tries = 0;
  while (true) {
    siginfo_t info_ptr;
    auto res = waitid(P_ALL, task_leader, &info_ptr, WEXITED | WSTOPPED | WNOWAIT);
    if (res == -1) {
      error_tries++;
      ASSERT(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
      continue;
    }
    error_tries = 0;
    // notify Tracer thread that it can pull out wait status info
    notifier.notify();
    {
      std::unique_lock lk(m);
      ready = false;
      while (!ready)
        cv.wait(lk);
    }
    ready = false;
  }
};

AwaiterThread::AwaiterThread(Notify notifier, Tid task_leader) noexcept
    : notifier(notifier), events_reaped(true), m{}, cv{}, initialized(false), should_cont(true)
{

  worker_thread = std::thread{[&n = this->notifier, &t = task_leader, &cv = cv, &m = m, &ready = events_reaped,
                               &initialized = initialized, &c = should_cont]() {
    int error_tries = 0;
    {
      std::unique_lock lk(m);
      while (!initialized) {
        cv.wait(lk);
      }
    }

    while (c) {
      siginfo_t info_ptr;
      auto res = waitid(P_ALL, t, &info_ptr, WEXITED | WSTOPPED | WNOWAIT);
      if (res == -1) {
        error_tries++;
        ASSERT(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
        continue;
      }
      error_tries = 0;
      // notify Tracer thread that it can pull out wait status info
      n.notify();
      {
        std::unique_lock lk(m);
        ready = false;
        while (!ready)
          cv.wait(lk);
      }
      ready = false;
    }
  }};
};

AwaiterThread::~AwaiterThread() noexcept { worker_thread.join(); }

void
AwaiterThread::reaped_events() noexcept
{
  events_reaped = true;
  cv.notify_one();
}

void
AwaiterThread::start_awaiter_thread() noexcept
{
  this->initialized = true;
  cv.notify_all();
}

void
AwaiterThread::set_process_exited() noexcept
{
  should_cont = false;
}
#include "awaiter.h"
#include "common.h"
#include "event_queue.h"
#include "supervisor.h"
#include "tracer.h"
#include <bits/chrono.h>
#include <bits/types/idtype_t.h>
#include <chrono>
#include <sys/wait.h>

AwaiterThread::AwaiterThread(Notify notifier, Tid task_leader) noexcept
    : notifier(notifier), events_reaped(true), m{}, cv{}, thread(), should_cont(true),
      process_group_id(task_leader){};

AwaiterThread::~AwaiterThread() noexcept
{
  should_cont = false;
  reaped_events();
  if (thread.joinable())
    thread.join();
}

void
AwaiterThread::reaped_events() noexcept
{
  events_reaped = true;
  cv.notify_one();
}

void
AwaiterThread::start_awaiter_thread(TraceeController *tc) noexcept
{
  thread = std::thread{[tc, &ready = events_reaped, &c = should_cont]() {
    int error_tries = 0;
    const auto pgid = -(tc->task_leader);
    while (c) {
      int status = 0;
      const auto res = waitpid(pgid, &status, 0 | __WALL);
      if (res == -1) {
        error_tries++;
        VERIFY(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
        continue;
      }
      DLOG("mdb", "[wait]: waited for {}", res);
      const auto wait_result = process_status(res, status);
      push_event(Event{.process_group = tc->task_leader, .type = EventType::WaitStatus, .wait = wait_result});
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
#pragma once
#include "common.h"
#include "notify_pipe.h"
#include <condition_variable>
#include <memory>
#include <thread>

using Notify = utils::Notifier::WriteEnd;

class AwaiterThread
{
public:
  using handle = std::unique_ptr<AwaiterThread>;
  AwaiterThread() = delete;
  /*
   * - `notifier` - the notifier mechanism for informing the Tracer thread that something can be done
   * - `task_leader` - the process space / task group leader / pid that we're awaiting on (and it's subsequent
   * children)
   */
  AwaiterThread(Notify notifier, Tid task_leader) noexcept;
  ~AwaiterThread() noexcept;

  AwaiterThread(AwaiterThread &&) = delete;
  NO_COPY(AwaiterThread);

  /** Inform the AwaiterThread that the events it reported, we have seen and dealt with, allow AwaiterThread to
   * listen for new events. If other threads of the process comes across WAIT events (i.e. become stopped), we will
   * witness them during the next wait events cycle. The main purpose of this function is to not have AwaiterThread
   * reporting events to Tracer that was actually caused by the Tracer thread itself; for instance, singlestepping
   * out of a syscall exit, or a continue-stop-continue cycle, etc.*/
  void reaped_events() noexcept;
  /** Inform AwaiterThread that we've initialized all the state required for it to start listening for events. */
  void start_awaiter_thread() noexcept;
  /** Inform AwaiterThread that the process it is waiting on, no longer is executing, i.e. let AwaiterThread
   * finish. */
  void set_process_exited() noexcept;

private:
  Notify notifier;
  bool events_reaped;
  std::mutex m;
  std::condition_variable cv;
  bool initialized;
  std::thread worker_thread;
  // The keep-alive variable. If the task leader exits, should_cont = false and AwaiterThread is done.
  bool should_cont;
};
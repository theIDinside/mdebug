#pragma once
#include "common.h"
#include "notify_pipe.h"
#include "utils/macros.h"
#include <condition_variable>
#include <memory>
#include <thread>

using Notify = utils::Notifier::WriteEnd;

namespace tc {
class TraceeCommandInterface;
}

class TraceeController;
class AwaiterThread
{
public:
  using handle = std::unique_ptr<AwaiterThread>;
  NO_NON_EXPLICIT_CTORS(AwaiterThread);

  explicit AwaiterThread(Tid task_leader) noexcept;
  ~AwaiterThread() noexcept;

  /** Inform AwaiterThread that we've initialized all the state required for it to start listening for events. */
  void start_awaiter_thread(tc::TraceeCommandInterface *tc) noexcept;
  /** Inform AwaiterThread that the process it is waiting on, no longer is executing, i.e. let AwaiterThread
   * finish. */
  void init_shutdown() noexcept;

private:
  std::thread thread;
  // The keep-alive variable. If the task leader exits, should_cont = false and AwaiterThread is done.
  bool keep_going;
  Tid process_group_id;
};
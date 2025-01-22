/** LICENSE TEMPLATE */
#pragma once
#include "notify_pipe.h"
#include "utils/debugger_thread.h"
#include "utils/macros.h"
#include <memory>
#include <thread>

using Notify = utils::Notifier::WriteEnd;

namespace tc {
class TraceeCommandInterface;
}

class TraceeController;

class WaitStatusReaderThread
{
  std::unique_ptr<DebuggerThread> mThread;
public:
  static std::unique_ptr<WaitStatusReaderThread> Init() noexcept;
  void Start() noexcept;
};
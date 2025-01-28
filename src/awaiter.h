/** LICENSE TEMPLATE */
#pragma once
#include "utils/debugger_thread.h"
#include <memory>

namespace mdb {
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
} // namespace mdb
/** LICENSE TEMPLATE */
#include "./utils/logger.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
#include "mdbjs/mdbjs.h"
#include "supervisor.h"
#include "tracer.h"
#include "utils/debugger_thread.h"
#include "utils/thread_pool.h"
#include <asm-generic/errno-base.h>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <fmt/core.h>
#include <linux/sched.h>
#include <mutex>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utils/expected.h>

std::mutex m;
std::condition_variable cv;
std::string data;
bool ready = false;
bool exit_debug_session = false;

mdb::Tracer *mdb::Tracer::sTracerInstance = nullptr;
mdb::js::AppScriptingInstance *mdb::Tracer::sScriptRuntime = nullptr;
JSContext *mdb::Tracer::sApplicationJsContext = nullptr;

termios mdb::Tracer::sOriginalTty = {};
winsize mdb::Tracer::sTerminalWindowSize = {};
bool mdb::Tracer::sUsePTraceMe = true;
mdb::TracerProcess mdb::Tracer::sApplicationState = TracerProcess::Running;

mdb::ThreadPool *mdb::ThreadPool::sGlobalThreadPool = new mdb::ThreadPool{};

int
main(int argc, const char **argv)
{
  // Sets main thread id. It's static so subsequent calls from other threads should be fine.
  mdb::GetMainThreadId();
  mdb::EventSystem *eventSystem = mdb::EventSystem::Initialize();

  auto res = mdb::sys::parse_cli(argc, argv);
  if (!res.is_expected()) {
    auto &&err = res.error();
    switch (err.info) {
    case mdb::sys::CLIErrorInfo::BadArgValue:
      fmt::println("Bad CLI argument value");
      break;
    case mdb::sys::CLIErrorInfo::UnknownArgs:
      fmt::println("Unknown CLI argument");
      break;
    }
    exit(-1);
  }

  const mdb::sys::DebuggerConfiguration &config = res.value();
  {
    using enum Channel;
    for (const auto id : Enum<Channel>::Variants()) {
      mdb::logging::Logger::GetLogger()->SetupChannel(config.LogDirectory(), id);
    }
  }

  std::span<const char *> args(argv, argc);
  namespace logging = mdb::logging;
  DBGLOG(core, "MDB CLI Arguments");
  for (const auto arg : args.subspan(1)) {
    DBGLOG(core, "{}", arg);
  }

  auto log = config.log_config();
  log.configure_logging(true);
  CDLOG(log.awaiter, core, "Setting awaiter log on");

  mdb::Tracer::Create(config);
  mdb::ThreadPool::GetGlobalPool()->Init(config.ThreadPoolSize());

#ifdef MDB_DEBUG

  // timeDelta is the last time this function was called. That way
  // The debug functions can decide if they should run or not.
  std::vector<std::function<void(std::chrono::milliseconds)>> intervalJobs{
    [delta = u64{0}](std::chrono::milliseconds timeDelta) mutable noexcept {
      delta += timeDelta.count();
      if (delta < 500) {
        return;
      }
      delta = 0;
      if (const auto &tasks = mdb::Tracer::Get().UnInitializedTasks(); !tasks.empty()) {
        std::string res;
        auto iter = std::back_inserter(res);
        for (const auto &[tid, task] : tasks) {
          iter = fmt::format_to(iter, "{}{}:{}", res.empty() ? '[' : ',', tid,
                                task->is_stopped() ? "stopped" : "running");
        }
        if (!res.empty()) {
          res.push_back(']');
        }

        DBGLOG(warning, "Tasks are still uninitialized, tasks={}", res);
      }
    },
    [events = u64{0}, stallTime = u64{0}, reported = false,
     writeBuffer = std::string{}](std::chrono::milliseconds interval) mutable noexcept {
      if (!mdb::Tracer::Get().SeenNewEvents(events)) {
        stallTime += interval.count();
        if (!reported) {
          writeBuffer.clear();
          for (const auto &target : mdb::Tracer::Get().mTracedProcesses) {
            for (const auto &entry : target->GetThreads()) {
              if (entry.mTask->can_continue()) {
                fmt::format_to(std::back_inserter(writeBuffer), "tid={}, stopped={}, wait={}, ?pc?=0x{:x}\n",
                               entry.mTid, entry.mTask->is_stopped(), to_str(entry.mTask->mLastWaitStatus.ws),
                               entry.mTask->get_register(16));
              }
            }
          }
          DBGLOG(warning, "Debug session task debug state:\n{}\nNo new debugger events processed in {}",
                 writeBuffer, stallTime);
        }
        reported = true;
        return;
      }
      stallTime = 0;
      events = mdb::Tracer::Get().DebuggerEventCount();
      reported = false;
    }};

  auto stateDebugThread = mdb::DebuggerThread::SpawnDebuggerThread(
    "MdbStateMonitor", [intervalJobs = std::move(intervalJobs)](std::stop_token &token) {
      constexpr auto intervalSetting = std::chrono::milliseconds{500};
      while (mdb::Tracer::Get().IsRunning() && !token.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{intervalSetting});
        for (auto &f : intervalJobs) {
          f(intervalSetting);
        }
      }
    });
#endif

  // spawn the UI thread that runs our UI loop
  bool ui_thread_setup = false;

  auto ui_thread =
    mdb::DebuggerThread::SpawnDebuggerThread("IO-Thread", [&ui_thread_setup](std::stop_token &token) {
      mdb::ui::dap::DAP ui_interface{STDIN_FILENO, STDOUT_FILENO};
      mdb::Tracer::Get().set_ui(&ui_interface);
      ui_thread_setup = true;
      ui_interface.StartIOPolling(token);
    });

  while (!ui_thread_setup) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }

  mdb::Tracer::InitInterpreterAndStartDebugger(eventSystem);

  mdb::ThreadPool::ShutdownGlobalPool();
  exit_debug_session = true;
  mdb::Tracer::Get().kill_ui();
  DBGLOG(core, "Exited...");
}
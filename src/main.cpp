/** LICENSE TEMPLATE */
#include "./utils/logger.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
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

Tracer *Tracer::sTracerInstance = nullptr;
termios Tracer::sOriginalTty = {};
winsize Tracer::sTerminalWindowSize = {};
bool Tracer::sUsePTraceMe = true;
TracerProcess Tracer::sApplicationState = TracerProcess::Running;

utils::ThreadPool *utils::ThreadPool::sGlobalThreadPool = new utils::ThreadPool{};

int
main(int argc, const char **argv)
{
  // Sets main thread id. It's static so subsequent calls from other threads should be fine.
  GetMainThreadId();
  EventSystem* eventSystem = EventSystem::Initialize();

  auto res = sys::parse_cli(argc, argv);
  if (!res.is_expected()) {
    auto &&err = res.error();
    switch (err.info) {
    case sys::CLIErrorInfo::BadArgValue:
      fmt::println("Bad CLI argument value");
      break;
    case sys::CLIErrorInfo::UnknownArgs:
      fmt::println("Unknown CLI argument");
      break;
    }
    exit(-1);
  }

  const sys::DebuggerConfiguration &config = res.value();
  {
    using enum Channel;
    for (const auto id : Enum<Channel>::Variants()) {
      logging::Logger::GetLogger()->SetupChannel(config.LogDirectory(), id);
    }
  }

  std::span<const char *> args(argv, argc);
  DBGLOG(core, "MDB CLI Arguments");
  for (const auto arg : args.subspan(1)) {
    DBGLOG(core, "{}", arg);
  }

  auto log = config.log_config();
  log.configure_logging(true);
  CDLOG(log.awaiter, core, "Setting awaiter log on");

  Tracer::Create(config);
  utils::ThreadPool::GetGlobalPool()->Init(config.ThreadPoolSize());

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
      if (const auto &tasks = Tracer::Get().UnInitializedTasks(); !tasks.empty()) {
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
      if (!Tracer::Get().SeenNewEvents(events)) {
        stallTime += interval.count();
        if (!reported) {
          writeBuffer.clear();
          for (const auto &target : Tracer::Get().mTracedProcesses) {
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
      events = Tracer::Get().DebuggerEventCount();
      reported = false;
    }};

  auto stateDebugThread = DebuggerThread::SpawnDebuggerThread(
    "MdbStateMonitor", [intervalJobs = std::move(intervalJobs)](std::stop_token &token) {
      constexpr auto intervalSetting = std::chrono::milliseconds{500};
      while (Tracer::Get().IsRunning() && !token.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{intervalSetting});
        for (auto &f : intervalJobs) {
          f(intervalSetting);
        }
      }
    });
#endif

  // spawn the UI thread that runs our UI loop
  bool ui_thread_setup = false;

  auto ui_thread = DebuggerThread::SpawnDebuggerThread("IO-Thread", [&ui_thread_setup](std::stop_token &token) {
    ui::dap::DAP ui_interface{STDIN_FILENO, STDOUT_FILENO};
    Tracer::Get().set_ui(&ui_interface);
    ui_thread_setup = true;
    ui_interface.StartIOPolling(token);
  });

  while (!ui_thread_setup) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }

  std::vector<Event> readInEvents{};
  readInEvents.reserve(128);

  while (Tracer::Get().IsRunning()) {

    if (system->PollBlocking(readInEvents)) {
      for (auto evt : readInEvents) {
#ifdef MDB_DEBUG
        Tracer::Get().DebuggerEventCount()++;
#endif
        switch (evt.type) {
        case EventType::WaitStatus: {
          DBGLOG(awaiter, "stop for {}: {}", evt.uWait.wait.tid, to_str(evt.uWait.wait.ws.ws));
          if (auto dbg_evt = Tracer::Get().ConvertWaitEvent(evt.uWait.wait); dbg_evt) {
            Tracer::Get().HandleTracerEvent(dbg_evt);
          }
        } break;
        case EventType::Command: {
          Tracer::Get().handle_command(evt.uCommand);
        } break;
        case EventType::TraceeEvent: {
          Tracer::Get().HandleTracerEvent(evt.uDebugger);
        } break;
        case EventType::Initialization:
          Tracer::Get().HandleInitEvent(evt.uDebugger);
          break;
        case EventType::Internal: {
          Tracer::Get().HandleInternalEvent(evt.uInternalEvent);
          break;
        }
        }
      }
      readInEvents.clear();
    }
  }
  utils::ThreadPool::ShutdownGlobalPool();
  exit_debug_session = true;
  Tracer::Get().kill_ui();
  DBGLOG(core, "Exited...");
}
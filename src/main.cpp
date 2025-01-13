/** LICENSE TEMPLATE */
#include "./utils/logger.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "supervisor.h"
#include "tracer.h"
#include "utils/scope_defer.h"
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

termios Tracer::original_tty = {};
winsize Tracer::ws = {};
bool Tracer::use_traceme = true;

utils::ThreadPool *utils::ThreadPool::global_thread_pool = new utils::ThreadPool{};

int
main(int argc, const char **argv)
{
  // Sets main thread id. It's static so subsequent calls from other threads should be fine.
  GetMainThreadId();
  auto system = EventSystem::Initialize();

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
      if (const auto &tasks = Tracer::Instance->UnInitializedTasks(); !tasks.empty()) {
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
      if (Tracer::Instance->mDebuggerEvents == events) {
        stallTime += interval.count();
        if (!reported) {
          writeBuffer.clear();
          for (const auto &target : Tracer::Instance->mTracedProcesses) {
            for (const auto &t : target->GetThreads()) {
              if (t->can_continue()) {
                fmt::format_to(std::back_inserter(writeBuffer), "tid={}, stopped={}, wait={}, ?pc?=0x{:x}\n",
                               t->mTid, t->is_stopped(), to_str(t->mLastWaitStatus.ws), t->get_register(16));
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
      events = Tracer::Instance->mDebuggerEvents;
      reported = false;
    }};

  std::thread stateDebugThread{[intervalJobs = std::move(intervalJobs)]() {
    constexpr auto intervalSetting = std::chrono::milliseconds{500};
    while (Tracer::Instance->KeepAlive) {
      std::this_thread::sleep_for(std::chrono::milliseconds{intervalSetting});
      for (auto &f : intervalJobs) {
        f(intervalSetting);
      }
    }
  }};
  ScopedDefer JoinThread{[&stateDebugThread]() { stateDebugThread.join(); }};
#endif

  const sys::DebuggerConfiguration &config = res.value();
  {
    using enum logging::Channel;
    for (const auto id : logging::DefaultChannels()) {
      logging::Logger::get_logger()->setup_channel(config.LogDirectory(), id);
    }
  }

  std::span<const char *> args(argv, argc);
  DBGLOG(core, "MDB CLI Arguments");
  for (const auto arg : args.subspan(1)) {
    DBGLOG(core, "{}", arg);
  }

  auto [io_read, io_write] = utils::Notifier::notify_pipe();

  auto log = config.log_config();
  log.configure_logging(true);
  CDLOG(log.awaiter, core, "Setting awaiter log on");

  utils::NotifyManager notifiers{io_read};
  Tracer::Instance = new Tracer{io_read, &notifiers, config};
  auto &tracer = *Tracer::Instance;
  // spawn the UI thread that runs our UI loop
  bool ui_thread_setup = false;

  std::thread ui_thread{[&ui_thread_setup]() {
    ui::dap::DAP ui_interface{Tracer::Instance, STDIN_FILENO, STDOUT_FILENO};
    Tracer::Instance->set_ui(&ui_interface);
    ui_thread_setup = true;
    ui_interface.start_interface();
  }};

  while (!ui_thread_setup) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }

  std::vector<Event> readInEvents{};
  readInEvents.reserve(128);

  while (Tracer::Instance->KeepAlive) {

    if (system->PollBlocking(readInEvents)) {
      for (auto evt : readInEvents) {
#ifdef MDB_DEBUG
        Tracer::Instance->mDebuggerEvents++;
#endif
        switch (evt.type) {
        case EventType::WaitStatus: {
          DBGLOG(awaiter, "stop for {}: {}", evt.uWait.wait.tid, to_str(evt.uWait.wait.ws.ws));
          if (auto dbg_evt = tracer.ConvertWaitEvent(evt.uWait.wait); dbg_evt) {
            tracer.HandleTracerEvent(dbg_evt);
          }
        } break;
        case EventType::Command: {
          tracer.handle_command(evt.uCommand);
        } break;
        case EventType::TraceeEvent: {
          tracer.HandleTracerEvent(evt.uDebugger);
        } break;
        case EventType::Initialization:
          tracer.HandleInitEvent(evt.uDebugger);
          break;
        case EventType::Internal: {
          tracer.HandleInternalEvent(evt.uInternalEvent);
          break;
        }
        }
      }
      readInEvents.clear();
    }
  }
  utils::ThreadPool::shutdown_global_pool();
  exit_debug_session = true;
  Tracer::Instance->kill_ui();
  ui_thread.join();
  DBGLOG(core, "Exited...");
}
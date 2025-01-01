/** COPYRIGHT TEMPLATE */
#include "./utils/logger.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "tracer.h"
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

  std::vector<utils::NotifyResult> notify_events{};
  while (Tracer::Instance->KeepAlive) {
    const auto evt = poll_event();
    switch (evt.type) {
    case EventType::WaitStatus: {
      if (const auto dbg_evt = tracer.ConvertWaitEvent(evt.wait.wait); dbg_evt) {
        tracer.handle_core_event(dbg_evt);
      }
    } break;
    case EventType::Command: {
      tracer.handle_command(evt.cmd);
    } break;
    case EventType::TraceeEvent: {
      tracer.handle_core_event(evt.debugger);
    } break;
    case EventType::Initialization:
      tracer.handle_init_event(evt.debugger);
      break;
    }
  }
  utils::ThreadPool::shutdown_global_pool();
  exit_debug_session = true;
  Tracer::Instance->kill_ui();
  ui_thread.join();
  DBGLOG(core, "Exited...");
}
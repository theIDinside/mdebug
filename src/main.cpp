/** COPYRIGHT TEMPLATE */
#include "./utils/logger.h"
#include "common.h"
#include "interface/dap/interface.h"
#include "notify_pipe.h"
#include "tracer.h"
#include <array>
#include <asm-generic/errno-base.h>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <linux/sched.h>
#include <mutex>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
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
#include <utility>

std::mutex m;
std::condition_variable cv;
std::string data;
bool ready = false;
bool exit_debug_session = false;

enum AwaitablePipes : u64
{
  AwaiterThread = 0,
  IOThread = 1
};

template <AwaitablePipes AP>
constexpr size_t
idx()
{
  return std::to_underlying(AP);
}

termios Tracer::original_tty = {};
winsize Tracer::ws = {};

int
main(int argc, const char **argv)
{
  logging::Logger::get_logger()->setup_channel("mdb");
  logging::Logger::get_logger()->setup_channel("dap");

  std::span<const char *> args(argv, argc);
  logging::get_logging()->log("mdb", "MDB CLI Arguments");
  for (const auto arg : args) {
    logging::get_logging()->log("mdb", fmt::format("{}", arg));
  }

  auto [io_read, io_write] = utils::Notifier::notify_pipe();

  utils::NotifyManager notifiers{io_read};
  Tracer::Instance = new Tracer{io_read, &notifiers};
  auto &tracer = *Tracer::Instance;
  // spawn the UI thread that runs our UI loop
  bool ui_thread_setup = false;

  std::thread ui_thread{[&io_write = io_write, &ui_thread_setup]() {
    ui::dap::DAP ui_interface{Tracer::Instance, STDIN_FILENO, STDOUT_FILENO, io_write};
    Tracer::Instance->set_ui(&ui_interface);
    ui_thread_setup = true;
    ui_interface.run_ui_loop();
  }};

  while (!ui_thread_setup) {
  }

  std::vector<utils::NotifyResult> notify_events{};
  for (;;) {
    if (notifiers.poll(1000)) {
      notifiers.has_wait_ready(notify_events);
      for (const auto target : notify_events) {
        // handle await events on `target`
        tracer.wait_for_tracee_events(target.pid);
      }
      // handle IO event
      if (notifiers.has_io_ready()) {
        tracer.execute_pending_commands();
      }
    }
  }
  exit_debug_session = true;
  Tracer::Instance->kill_ui();
  ui_thread.join();
  fmt::println("Exited...");
}
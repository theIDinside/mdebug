/** COPYRIGHT TEMPLATE */
#include "./utils/logger.h"
#include "common.h"
#include "interface/dap/interface.h"
#include "notify_pipe.h"
#include "tracer.h"
#include "utils/thread_pool.h"
#include <asm-generic/errno-base.h>
#include <condition_variable>
#include <csignal>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <linux/sched.h>
#include <mutex>
#include <signal.h>
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

termios Tracer::original_tty = {};
winsize Tracer::ws = {};
bool Tracer::use_traceme = true;

utils::ThreadPool *utils::ThreadPool::global_thread_pool = new utils::ThreadPool{};

int
main(int argc, const char **argv)
{
  logging::Logger::get_logger()->setup_channel("mdb");
  logging::Logger::get_logger()->setup_channel("dap");
  logging::Logger::get_logger()->setup_channel("dwarf");
  logging::Logger::get_logger()->setup_channel("awaiter");
  logging::Logger::get_logger()->setup_channel("eh");
  utils::ThreadPool::get_global_pool()->initialize(8);

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
  while (Tracer::Instance->KeepAlive) {
    if (notifiers.poll(0)) {
      notifiers.has_wait_ready(notify_events, true);
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
  Tracer::Instance->kill_ui();
  Tracer::Instance->kill_all_targets();
  ui_thread.join();
  DLOG("mdb", "Exited...");
}
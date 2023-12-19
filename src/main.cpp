/** COPYRIGHT TEMPLATE */
#include "./utils/logger.h"
#include "common.h"
#include "event_queue.h"
#include "interface/dap/interface.h"
#include "mdb_config.h"
#include "notify_pipe.h"
#include "tracer.h"
#include "utils/thread_pool.h"
#include <array>
#include <asm-generic/errno-base.h>
#include <chrono>
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

static constexpr auto default_log_channels = {"mdb", "dap", "dwarf", "awaiter", "eh"};

int
main(int argc, const char **argv)
{
  for (const auto &channel : default_log_channels) {
    logging::Logger::get_logger()->setup_channel(channel);
  }
  auto res = sys::parse_cli(argc, argv);
  if (!res.is_expected()) {
    switch (res.error()) {
    case sys::CLIError::BadArgValue:
      fmt::println("Bad CLI argument value");
      break;
    case sys::CLIError::UnknownArgs:
      fmt::println("Unknown CLI argument");
      break;
    }
    exit(-1);
  }
  std::span<const char *> args(argv, argc);
  logging::get_logging()->log("mdb", "MDB CLI Arguments");
  for (const auto arg : args.subspan(1)) {
    logging::get_logging()->log("mdb", fmt::format("{}", arg));
  }

  auto [io_read, io_write] = utils::Notifier::notify_pipe();

  utils::NotifyManager notifiers{io_read};
  Tracer::Instance = new Tracer{io_read, &notifiers, res.value()};
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
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  }

  std::vector<utils::NotifyResult> notify_events{};
  while (Tracer::Instance->KeepAlive) {
    const auto evt = poll_event();
    switch (evt.type) {
    case EventType::WaitStatus: {
      tracer.handle_wait_event(evt.process_group, evt.wait);
    } break;
    case EventType::Command: {
      tracer.handle_command(evt.cmd);
      break;
    }
    }
  }
  exit_debug_session = true;
  Tracer::Instance->kill_ui();
  Tracer::Instance->kill_all_targets();
  ui_thread.join();
  DLOG("mdb", "Exited...");
}
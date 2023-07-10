/** COPYRIGHT TEMPLATE */
#include "common.h"
#include "interface/dap/interface.h"
#include "interface/pty.h"
#include "posix/argslist.h"
#include "target.h"
#include "tracer.h"
#include <array>
#include <asm-generic/errno-base.h>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fmt/core.h>
#include <linux/sched.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

int
main(int argc, const char **argv)
{

  if (argc < 2) {
    fmt::print("Usage: mdb <binary>\n");
    exit(EXIT_FAILURE);
  }

  fs::path p{argv[1]};
  if (!fs::exists(p)) {
    fmt::print("{} does not exist\n", p.c_str());
    exit(EXIT_FAILURE);
  }

  ScopedFd log_file = ScopedFd::open("/home/cx/dev/foss/cx/dbm/build-debug/bin/mdb.log", O_CREAT | O_RDWR);
  PosixArgsList args_list{std::vector<std::string>{argv + 1, argv + argc}};

  termios original_tty;
  winsize ws;
  VERIFY(tcgetattr(STDIN_FILENO, &original_tty) != -1, "Failed to get attributes for stdin");
  VERIFY(ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0, "Failed to get winsize of stdin");

  auto fork_result = pty_fork(&original_tty, &ws);

  switch (fork_result.index()) {
  case 0: {
    const auto [cmd, args] = args_list.get_command();
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
      PANIC("Failed to set ADDR_NO_RANDOMIZE!");
    }
    // ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    execv(cmd, args);
    break;
  }
  default: {
    const auto result = std::get<PtyParentResult>(fork_result);
    Tracer::Instance = new Tracer{};
    auto &tracer = *Tracer::Instance;
    // spawn the UI thread that runs our UI loop
    std::thread ui_thread{[fd = result.fd]() {
      ui::dap::DAP ui_interface{Tracer::Instance, STDIN_FILENO, STDOUT_FILENO, fd};
      Tracer::Instance->set_ui(&ui_interface);
      ui_interface.run_ui_loop();
    }};

    sleep(1);
    Tracer::Instance->add_target_set_current(result.pid, p);
    bool stopped = true;
    for (; tracer.get_current()->running();) {
      if (stopped) {
        tracer.continue_current_target();
      } else {
        tracer.get_current()->set_all_running(RunType::Continue);
      }
      stopped = tracer.wait_for_tracee_events();
    }
    Tracer::Instance->kill_ui();
    ui_thread.join();
    break;
  }
  }
  fmt::println("Exited...");
}
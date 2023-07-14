/** COPYRIGHT TEMPLATE */
#include "common.h"
#include "interface/dap/interface.h"
#include "interface/pty.h"
#include "notify_pipe.h"
#include "posix/argslist.h"
#include "target.h"
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

    auto [wait_read, wait_write] = utils::Notifier::notify_pipe();
    auto [io_read, io_write] = utils::Notifier::notify_pipe();

    utils::NotifyManager<2> notifiers{std::array<utils::Notifier::ReadEnd, 2>{wait_read, io_read},
                                      std::array<std::string_view, 2>{"Awaiter Thread", "IO Thread"}};

    Tracer::Instance = new Tracer{wait_read, io_read};
    auto &tracer = *Tracer::Instance;
    // spawn the UI thread that runs our UI loop
    bool ui_thread_setup = false;

    std::thread ui_thread{[fd = result.fd, &io_write = io_write, &ui_thread_setup]() {
      ui::dap::DAP ui_interface{Tracer::Instance, STDIN_FILENO, STDOUT_FILENO, fd, io_write};
      Tracer::Instance->set_ui(&ui_interface);
      ui_thread_setup = true;
      ui_interface.run_ui_loop();
    }};
    bool waiter_thread_setup = false;
    std::thread awaiter_thread([&wait_write = wait_write, tl = result.pid, &waiter_thread_setup]() {
      int error_tries = 0;
      waiter_thread_setup = true;
      while (!exit_debug_session) {

        siginfo_t info_ptr;
        auto res = waitid(P_ALL, tl, &info_ptr, WEXITED | WSTOPPED | WNOWAIT);
        if (res == -1) {
          error_tries++;
          ASSERT(error_tries <= 10, "Waitpid kept erroring out! {}: {}", errno, strerror(errno));
          continue;
        }
        error_tries = 0;
        // notify Tracer thread that it can pull out wait status info
        wait_write.notify();

        // Now wait for Tracer thread to notify us that it has handled all wait statuses it can
        // This is also very important for another reason; When the tracer thread does it's magic
        // it might for instance do start-stop-restart-stop LWP's for a number of reasons - while doing that,
        // we can't have the awaiter thread yelling at us that there are a bunch of new await results available
        // - so we tell this puppy to go to sleep here and let the Tracer thread wake it up afterwards
        {
          std::unique_lock lk(m);
          ready = false;
          while (!ready)
            cv.wait(lk);
        }
        ready = false;
      }
    });

    while (!waiter_thread_setup || !ui_thread_setup) {
    }
    Tracer::Instance->add_target_set_current(result.pid, p);
    bool stopped = true;
    using enum AwaitablePipes;
    for (; tracer.get_current()->execution_not_ended();) {
      if (notifiers.poll(1000)) {
        if (notifiers.has_notification<AwaiterThread>()) {
          stopped = tracer.wait_for_tracee_events();
          ready = true;
          cv.notify_one();
        }
        if (notifiers.has_notification<IOThread>()) {
          tracer.execute_pending_commands();
        }
      }
      if (stopped) {
        fmt::println("Tracer reported we're stopped?");
      }
    }
    exit_debug_session = true;
    Tracer::Instance->kill_ui();
    ui_thread.join();
    awaiter_thread.join();
    break;
  }
  }
  fmt::println("Exited...");
}
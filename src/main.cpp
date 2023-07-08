/** COPYRIGHT TEMPLATE */
#include "common.h"
#include "posix/argslist.h"
#include "target.h"
#include "task.h"
#include "tracer.h"
#include <cstdlib>
#include <filesystem>
#include <fmt/core.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>

#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/sched.h>
#include <sched.h>

#include <csignal>

#include "ptrace.h"
#include <sys/personality.h>

#include "interface/dap/interface.h"

static int barrier[2];

// Signal handler function

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

  PosixArgsList args_list{std::vector<std::string>{argv + 1, argv + argc}};
  if (-1 == pipe(barrier)) {
    PANIC("Failed to set up barrier pipes\n");
  }

  auto pid = fork();
  switch (pid) {
  case 0: {
    const auto [cmd, args] = args_list.get_command();
    if (personality(ADDR_NO_RANDOMIZE) == -1) {
      PANIC("Failed to set ADDR_NO_RANDOMIZE!");
    }
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);
    execv(cmd, args);
  } break;
  default: {
    Tracer tracer{};
    ui::dap::DAP ui_interface{&tracer, 1, 0};
    Tracer::Instance->add_target_set_current(pid, p);

    // the event loop
    // For now, before we've implemented a pseudo terminal, that can act as our "tracee terminal"
    // we'll just do the following;
    // if we're running, wait for tracee events
    // if not, wait for UI events (like user input)
    // This means that UI actions can never be asynchronous and only ever happen
    // at tracee stops - but, it is *by design* it's done that way for now, because it's orders of magnitude
    // easier to get to a working state, in order to build the other interesting stuff that
    // we want to build. But in the final design, we won't be doing if-else, but instead have some
    // sort of event pump that gives us events to track and handle accordingly, where the events
    // can come from multiple sources
    // But doing the above, means we can start developing our DAP interface and start testing it
    for (;;) {
      if (tracer.waiting_for_ui()) {
        tracer.wait_and_process_ui_events();
      } else {
        tracer.wait_for_tracee_events();
      }
    }
    break;
  }
  }
}
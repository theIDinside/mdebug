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
    tracer.init_io_thread();
    Tracer::Instance->add_target_set_current(pid, p);
    auto target = tracer.get_current();
    auto current_task = target->get_task(pid);

    // todo(simon): for now, support only 1 process space (target), though the design looks as though we support
    // multiple.

    auto tracee_exited = false;
    while (!tracee_exited) {
      auto wait = target->wait_pid(current_task);
      target->set_wait_status(wait);
      switch (wait.ws) {
      case WaitStatus::Stopped:
        break;
      case WaitStatus::Execed: {
        tracer.get_current()->reopen_memfd();
        target->read_auxv(wait);
        break;
      }
      case WaitStatus::Exited: {
        if (wait.waited_pid == tracer.get_current()->task_leader) {
          tracee_exited = true;
        }
        break;
      }
      case WaitStatus::Cloned: {
        const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(wait.registers);
        const auto res = target->read_type(ptr);
        // Nasty way to get PID, but, in doing so, we also get stack size + stack location for new thread
        auto np = target->read_type(TPtr<pid_t>{res.parent_tid});
#ifdef MDB_DEBUG
        long new_pid = 0;
        PTRACE_OR_PANIC(PTRACE_GETEVENTMSG, wait.waited_pid, 0, &new_pid);
        ASSERT(np == new_pid, "Inconsistent pid values retrieved, expected {} but got {}", np, new_pid);
#endif
        target->new_task(np);
        target->set_task_vm_info(np, TaskVMInfo::from_clone_args(res));
        target->get_task(np)->request_registers();
        break;
      }
      case WaitStatus::Forked:
        break;
      case WaitStatus::VForked:
        break;
      case WaitStatus::VForkDone:
        break;
      case WaitStatus::Signalled:
        break;
      case WaitStatus::SyscallEntry:
        break;
      case WaitStatus::SyscallExit:
        break;
      }
      sleep(1);
      target->set_running(RunType::Continue);
    }
    break;
  }
  }
}
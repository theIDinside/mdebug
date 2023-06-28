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
    char c;
    read(barrier[0], &c, 1);
    execv(cmd, args);
  } break;
  default: {
    PTRACE_OR_PANIC(PTRACE_ATTACH, pid, nullptr, nullptr);
    Tracer tracer{};
    write(barrier[1], "1", 1);
    Tracer::Instance->add_target(pid, p);
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
        break;
      }
      case WaitStatus::Exited: {
        if (wait.waited_pid == tracer.get_current()->task_leader) {
          tracee_exited = true;
        }
        break;
      }
      case WaitStatus::Cloned: {
        const TraceePointer<clone_args> cl_args_ptr = sys_arg<SysRegister::RDI>(wait.registers);
        if (auto res = target->read_type(cl_args_ptr); res.has_value()) {
          TraceePointer<pid_t> new_pid_ptr{res->parent_tid};
          auto np = target->read_type(new_pid_ptr);
          if(np.has_value()) {

            #ifdef MDB_DEBUG
            long new_pid = 0;
            PTRACE_OR_PANIC(PTRACE_GETEVENTMSG, wait.waited_pid, 0, &new_pid);
            ASSERT(np.value() == new_pid, "Inconsistent pid values retrieved, expected {} but got {}", np.value(), new_pid);
            #endif

            target->new_task(np.value());
            target->set_task_vm_info(np.value(), TaskVMInfo{.stack_low = res->stack, .stack_size = res->stack_size, .tls = res->tls});
            target->get_task(np.value())->request_registers();
          } else {
            fmt::println("FAILED TO SET NEW TASK");
          }
        }
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
      target->set_running(RunType::Continue);
    }
    break;
  }
  }
}
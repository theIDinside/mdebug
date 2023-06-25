/** COPYRIGHT TEMPLATE */
#include "common.h"
#include "posix/argslist.h"
#include "ptrace.h"
#include "target.h"
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

static int barrier[2];

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
    panic("Failed to set up barrier pipes\n");
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
    ptrace_or_panic(PTRACE_ATTACH, pid);
    Tracer tracer{};
    write(barrier[1], "1", 1);
    int status = 0;
    waitpid(pid, &status, 0);
    tracer.add_target(pid, p);
    auto tracee_exited = false;
    ptrace_or_panic(PTRACE_SYSCALL, pid);
    while (!tracee_exited) {

      auto waited_pid = waitpid(0, &status, 0);
      if (!WIFEXITED(status)) {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, waited_pid, NULL, &regs);
        __ptrace_syscall_info ptr;
        constexpr auto size = sizeof(__ptrace_syscall_info);
        ptrace_or_panic(PTRACE_GET_SYSCALL_INFO, waited_pid, size, &ptr);
        if (ptr.op == PTRACE_SYSCALL_INFO_NONE) {

        } else {
          const auto &info = (PtraceSyscallInfo &)ptr;
          if (info.is_exit()) {
            if ((regs.orig_rax == SYS_execve || regs.orig_rax == SYS_execveat)) {
              auto &target = tracer.get_target(waited_pid);
              target.reopen_memfd();
            } else if ((regs.orig_rax == SYS_clone || regs.orig_rax == SYS_clone3)) {
              SyscallArguments args{regs};
              TraceePointer<clone_args> cl_args_address = args.arguments.rdi;
              auto &target = tracer.get_target(waited_pid);
              // Example of how to use TraceePointer and Targt::read_type
              if (auto res = target.read_type(cl_args_address, waited_pid); res.has_value()) {
                auto cl_args = res.value();
                TraceePointer<pid_t> new_pid = (uintptr_t)cl_args.parent_tid;
                auto np = target.read_type(new_pid, waited_pid);
                if (np.has_value())
                  fmt::println("[PROCFS] COULD FIND: {} pid?", np.value());
              }
              tracer.new_thread(waited_pid, ptr.exit.rval);
            }
          }
        }

        ptrace_or_panic(PTRACE_SYSCALL, waited_pid);
      } else if (WIFEXITED(status)) {
        fmt::println("{} exited with {}", waited_pid, WEXITSTATUS(status));
        tracer.thread_exited(waited_pid, status);
        if (waited_pid == pid) {
          fmt::println("Process exited...");
          tracee_exited = true;
        }
      }
    }
    break;
  }
  }
}
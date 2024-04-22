#pragma once

#include "awaiter.h"
#include "tracee_command_interface.h"
#include "utils/macros.h"
#include <utils/scoped_fd.h>

struct TraceeController;

namespace tc {
class PtraceCommander final : public TraceeCommandInterface
{
  utils::ScopedFd procfs_memfd;
  AwaiterThread::handle awaiter_thread;
  Tid process_id;

public:
  NO_COPY(PtraceCommander);
  explicit PtraceCommander(Tid task_leader) noexcept;

  TraceeReadResult read_bytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult write_bytes(AddrPtr addr, u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse resume_task(TaskInfo &t, RunType type) noexcept final;
  TaskExecuteResponse stop_task(TaskInfo &t) noexcept final;
  TaskExecuteResponse enable_breakpoint(BreakpointLocation &location) noexcept final;
  TaskExecuteResponse disable_breakpoint(BreakpointLocation &location) noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse install_breakpoint(AddrPtr addr) noexcept final;

  TaskExecuteResponse read_registers(TaskInfo &t) noexcept final;
  TaskExecuteResponse write_registers(const user_regs_struct &input) noexcept final;
  TaskExecuteResponse set_pc(const TaskInfo &t, AddrPtr addr) noexcept final;

  TaskExecuteResponse disconnect(bool terminate) noexcept final;
  bool perform_shutdown() noexcept final;
  bool initialize() noexcept final;

  bool reconfigure(TraceeController *) noexcept final;
  Tid task_leader() const noexcept final;
};
} // namespace tc
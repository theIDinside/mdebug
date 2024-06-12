#pragma once

#include "awaiter.h"
#include "tracee_command_interface.h"
#include "utils/macros.h"
#include <link.h>
#include <utils/scoped_fd.h>

struct TraceeController;

namespace tc {

struct ProcessState
{
  utils::ScopedFd procfs_memfd;
  AwaiterThread::handle awaiter_thread;
  Tid process_id;
  TPtr<r_debug_extended> tracee_r_debug{nullptr};
};

class PtraceCommander final : public TraceeCommandInterface
{
  utils::ScopedFd procfs_memfd;
  AwaiterThread::handle awaiter_thread;
  Tid process_id;
  TPtr<r_debug_extended> tracee_r_debug{nullptr};

  std::unordered_map<Tid, std::string> thread_names{};

public:
  NO_COPY(PtraceCommander);
  explicit PtraceCommander(Tid task_leader) noexcept;
  ~PtraceCommander() noexcept override = default;

  // TRACEE COMMAND INTERFACE API
  ReadResult read_bytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult write_bytes(AddrPtr addr, u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse resume_task(TaskInfo &t, RunType type) noexcept final;
  TaskExecuteResponse resume_target(TraceeController *tc, RunType run) noexcept final;
  TaskExecuteResponse stop_task(TaskInfo &t) noexcept final;
  TaskExecuteResponse enable_breakpoint(BreakpointLocation &location) noexcept final;
  TaskExecuteResponse disable_breakpoint(BreakpointLocation &location) noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse install_breakpoint(AddrPtr addr) noexcept final;

  TaskExecuteResponse read_registers(TaskInfo &t) noexcept final;
  TaskExecuteResponse write_registers(const user_regs_struct &input) noexcept final;
  TaskExecuteResponse set_pc(const TaskInfo &t, AddrPtr addr) noexcept final;

  std::string_view get_thread_name(Tid tid) noexcept final;

  TaskExecuteResponse disconnect(bool kill_target) noexcept final;
  bool perform_shutdown() noexcept final;
  bool initialize() noexcept final;

  /// Re-open proc fs mem file descriptor. Configure
  bool post_exec() noexcept final;
  // Called after a fork for the creation of a new process supervisor
  Interface on_fork(Pid pid) noexcept final;

  Tid task_leader() const noexcept final;
  std::optional<Path> execed_file() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> read_libraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> remote_connection() noexcept final;
  utils::Expected<Auxv, Error> read_auxv() noexcept final;
  //
};
} // namespace tc
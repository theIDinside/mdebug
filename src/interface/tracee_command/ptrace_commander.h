#pragma once

#include "awaiter.h"
#include "tracee_command_interface.h"
#include "utils/macros.h"
#include <link.h>
#include <utils/scoped_fd.h>

class TraceeController;

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

  std::unordered_map<Tid, std::string> thread_names{};

public:
  NO_COPY(PtraceCommander);
  explicit PtraceCommander(Tid task_leader) noexcept;
  ~PtraceCommander() noexcept override = default;

  // TRACEE COMMAND INTERFACE API
  ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult WriteBytes(AddrPtr addr, u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse ResumeTask(TaskInfo &t, RunType type) noexcept final;
  TaskExecuteResponse ResumeTarget(TraceeController *tc, RunType run) noexcept final;
  TaskExecuteResponse StopTask(TaskInfo &t) noexcept final;
  TaskExecuteResponse EnableBreakpoint(BreakpointLocation &location) noexcept final;
  TaskExecuteResponse DisableBreakpoint(BreakpointLocation &location) noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse InstallBreakpoint(AddrPtr addr) noexcept final;

  TaskExecuteResponse ReadRegisters(TaskInfo &t) noexcept final;
  TaskExecuteResponse WriteRegisters(const user_regs_struct &input) noexcept final;
  TaskExecuteResponse SetProgramCounter(const TaskInfo &t, AddrPtr addr) noexcept final;

  std::string_view GetThreadName(Tid tid) noexcept final;

  TaskExecuteResponse Disconnect(bool kill_target) noexcept final;
  bool PerformShutdown() noexcept final;
  bool Initialize() noexcept final;

  /// Re-open proc fs mem file descriptor. Configure
  bool OnExec() noexcept final;
  // Called after a fork for the creation of a new process supervisor
  Interface OnFork(Pid pid) noexcept final;

  Tid TaskLeaderTid() const noexcept final;
  std::optional<Path> ExecedFile() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept final;
  utils::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept final;
  //
};
} // namespace tc
/** LICENSE TEMPLATE */
#pragma once

#include "tracee_command_interface.h"
#include "utils/macros.h"
#include <link.h>
#include <utils/scoped_fd.h>

class TraceeController;

namespace mdb::tc {

class PtraceCommander final : public TraceeCommandInterface
{
  mdb::ScopedFd procfs_memfd;
  Tid process_id;

  std::unordered_map<Tid, std::string> thread_names{};

public:
  NO_COPY(PtraceCommander);
  explicit PtraceCommander(Tid task_leader) noexcept;
  ~PtraceCommander() noexcept override = default;

  // TRACEE COMMAND INTERFACE API
  ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse ResumeTask(TaskInfo &t, ResumeAction resume) noexcept final;
  TaskExecuteResponse ResumeTarget(TraceeController *tc, ResumeAction action) noexcept final;
  TaskExecuteResponse StopTask(TaskInfo &t) noexcept final;
  TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept final;

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
  bool PostFork(TraceeController *parent) noexcept final;

  Tid TaskLeaderTid() const noexcept final;
  std::optional<Path> ExecedFile() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept final;
  mdb::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept final;
  //
};
} // namespace mdb::tc
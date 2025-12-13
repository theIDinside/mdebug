/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common/macros.h>
#include <interface/rr/rr_supervisor.h>
#include <interface/tracee_command/tracee_command_interface.h>
#include <utils/scoped_fd.h>

namespace rr {
class SupervisorLibrary;
}

namespace mdb::tc {

class RR final : public TraceeCommandInterface
{
  mdbrr::ReplaySupervisor *mReplaySupervisor;
  Tid mTaskLeader;

  mdbrr::ReplaySupervisor *GetSupervisor() noexcept;
  std::unordered_map<Tid, std::string> mThreadNames;

  // When a thread is first seen, we store it here, and it's kept here forever after that
  // so if we reverse/replay across the boundary where it's either born or dies, we can resurrect it by just
  // looking it up in this map.
  std::unordered_map<Tid, RefPtr<TaskInfo>> mTraceThreads{};

public:
  NO_COPY(RR);
  explicit RR(Tid taskLeaderId, mdbrr::ReplaySupervisor *replaySupervisor) noexcept;
  ~RR() noexcept override = default;

  // TRACEE COMMAND INTERFACE API
  ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept final;

  RefPtr<TaskInfo> CreateNewTask(Tid tid, bool isRunning) noexcept final;
  TaskExecuteResponse ReverseContinue(bool onlyStep) noexcept final;

  TaskExecuteResponse ResumeTask(TaskInfo &t, RunType resumeType) noexcept final;
  TaskExecuteResponse ResumeTarget(RunType resumeType, std::vector<Tid> *resumedThreads = nullptr) noexcept final;
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

  /// Re-open proc fs mem file descriptor. Configure
  bool OnExec() noexcept final;
  // Called after a fork for the creation of a new process supervisor
  Interface OnFork(SessionId pid) noexcept final;
  bool PostFork(TraceeController *parent) noexcept final;

  bool
  IsAllStopSession() noexcept final
  {
    return true;
  }

  Tid TaskLeaderTid() const noexcept final;
  std::optional<Path> ExecedFile() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept final;
  mdb::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept final;
  void OnTaskExit(TaskInfo &task) noexcept final;
  void OnTaskCreated(TaskInfo &task) noexcept final;
  //
};
} // namespace mdb::tc
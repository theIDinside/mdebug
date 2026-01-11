/** LICENSE TEMPLATE */
#pragma once

#include <event_queue_types.h>
#include <interface/tracee_command/supervisor_state.h>

namespace rr {
class ReplayTask;
}

namespace mdb::tc::replay {

class ReplaySupervisor;

class Session final : public SupervisorState
{
private: // members
  ReplaySupervisor *mReplaySupervisor;
  bool mExited{ false };

  // Flag for if this process has done any replaying. On fork, a process will be created, but it may not have
  // executed yet.
  bool mHasFirstExecuted{ false };

  std::optional<SessionId> mParentSessionId{ std::nullopt };
  std::optional<ReplayEvent> mDeferredEvent{ std::nullopt };

private: // methods
  Session(ReplaySupervisor *replaySupervisor, Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept;

  rr::ReplayTask *GetReplayTask(Tid recTid) noexcept;
  std::optional<std::string> GetThreadName(Tid tid) noexcept;

public:
  static Session *Create(ReplaySupervisor *replaySupervisor,
    std::optional<SessionId> sessionId,
    Tid taskLeader,
    ui::dap::DebugAdapterManager *dap,
    bool hasReplayedStep) noexcept;

  ReplaySupervisor *GetReplaySupervisor() const noexcept;
  void HandleEvent(const ReplayEvent &event) noexcept;

  // Implementation of SupervisorState interface
private:
  // Called after a fork for the creation of a new process supervisor
  void HandleFork(TaskInfo &parentTask, pid_t child, bool vFork) noexcept final;
  mdb::Expected<Auxv, Error> DoReadAuxiliaryVector() noexcept final;
  void InitRegisterCacheFor(const TaskInfo &task) noexcept final;

protected:
  bool PerformShutdown() noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept final;

public:
  TaskExecuteResponse ReadRegisters(TaskInfo &t) noexcept final;
  TaskExecuteResponse WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept final;
  TaskExecuteResponse SetRegister(TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept final;
  // Used for normal debugging operations. Retrieving special registers is uninteresting from a debugger interface
  // perspective and as such should be handled specifically. For instance, unwinding the stack which is a very
  // common operation, relies solely on user registers and never anything else. locations of types and objects, are
  // defined by DWARF operations and these also, never use special registers. If this changes, just change this
  // interface to account for special registers as well.
  u64 GetUserRegister(const TaskInfo &t, size_t registerNumber) noexcept final;

  TaskExecuteResponse DoDisconnect(bool terminate) noexcept final;
  ReadResult DoReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  // Can (possibly) modify state in `t`
  TaskExecuteResponse StopTask(TaskInfo &t) noexcept final;
  void DoResumeTask(TaskInfo &t, RunType type) noexcept final;
  bool DoResumeTarget(RunType type) noexcept final;
  bool ReverseResumeTarget(tc::RunType type) noexcept final;
  void AttachSession(ui::dap::DebugAdapterSession &session) noexcept final;
  bool Pause(Tid tid) noexcept final;
};
} // namespace mdb::tc::replay
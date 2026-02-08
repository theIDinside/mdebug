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
  bool mRevived{ false };
  uint64_t mGenesisFrame{ UINT64_MAX };

  Pid mParenPid{ 0 };
  std::optional<ReplayEvent> mDeferredEvent{ std::nullopt };

private: // methods
  Session(ReplaySupervisor *replaySupervisor,
    Tid taskLeader,
    uint64_t frameTime,
    ui::dap::DebugAdapterManager *dap) noexcept;

  rr::ReplayTask *GetReplayTask(Tid recTid) noexcept;
  std::optional<std::string> GetThreadName(Tid tid) noexcept;
  TaskInfo *CreateNewTask(Tid tid, std::optional<std::string_view> name, bool running) noexcept;

public:
  static Session *Create(ReplaySupervisor *replaySupervisor,
    Tid taskLeader,
    ui::dap::DebugAdapterManager *dap,
    bool hasReplayedStep) noexcept;

  ReplaySupervisor *GetReplaySupervisor() const noexcept;
  void StoppedDuringReverse() noexcept;
  void DisconnectDueToReverse();
  void HandleEvent(const ReplayEvent &event) noexcept;

  // Returns true if we should keep reversing, false if we hit a breakpoint that we should report and abort
  // reversing for
  bool HandleBreakpointHitInReverse(TaskInfo &task, const RefPtr<BreakpointLocation> &breakpointLocation) noexcept;
  void HandleEventInReverse(const ReplayEvent &event) noexcept;

  void Revive() noexcept;
  bool
  FrameTimeYoungerThanGenesis(uint64_t time) const
  {
    DBGLOG(core, "[replay]: genesis time {}; compared to time {}", mGenesisFrame, time);
    return time < mGenesisFrame;
  }

  // Implementation of SupervisorState interface
private:
  // Called after a fork for the creation of a new process supervisor
  void HandleFork(TaskInfo &parentTask, pid_t child, bool vFork) noexcept final;
  void AdjustSymbols() noexcept;
  mdb::Expected<Auxv, Error> DoReadAuxiliaryVector() noexcept final;

protected:
  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept final;

  void UpdateInstructionBreakpoints(
    std::span<const BreakpointSpecification> add, std::span<const BreakpointSpecification> remove);

  void UpdateFunctionBreakpoints(
    std::span<const BreakpointSpecification> add, std::span<const BreakpointSpecification> remove);

public:
  void UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
    std::span<const BreakpointSpecification> add,
    std::span<const BreakpointSpecification> remove) noexcept final;
  // rr session override some DAP commands, as they're supposed to (possibly) affect multiple supervisor via one
  // shared interface.
  void SetSourceBreakpoints(
    const std::filesystem::path &sourceFilePath, const Set<BreakpointSpecification> &bps) noexcept final;
  void SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept final;
  void SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept final;
  void DoBreakpointsUpdate(const SymbolFile &newSymbolFile) noexcept;
  void DoBreakpointsUpdate(std::span<std::shared_ptr<SymbolFile>> newSymbolFiles) noexcept final;

  void OnErase() noexcept final;
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
  ReadResult DoReadBytes(AddrPtr address, u64 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult DoWriteBytes(AddrPtr addr, const u8 *buf, u64 size) noexcept final;

  TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  // Can (possibly) modify state in `t`
  TaskExecuteResponse StopTask(TaskInfo &t) noexcept final;
  void DoResumeTask(TaskInfo &t, RunType type) noexcept final;
  bool DoResumeTarget(RunType type) noexcept final;
  bool ReverseResumeTarget(tc::RunType type) noexcept final;
  bool Pause(Tid tid) noexcept final;
  mdb::ui::dap::StoppedEvent *CreateStoppedEvent(ui::dap::StoppedReason reason,
    std::string_view description,
    Tid tid,
    std::string_view text,
    bool allStopped,
    std::vector<int> breakpointsHit = {}) noexcept final;

  bool
  SingleThreadControl() const noexcept final
  {
    return false;
  }
};
} // namespace mdb::tc::replay
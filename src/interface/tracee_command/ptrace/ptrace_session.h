/** LICENSE TEMPLATE */
#pragma once

#include <event_queue_types.h>
#include <interface/event_handler_stack.h>
#include <interface/tracee_command/supervisor_state.h>
#include <mdbsys/stop_status.h>
#include <memory_resource>
#include <sys/user.h>
#include <utils/scoped_fd.h>

// system

namespace mdb::ui::dap {
class DebugAdapterManager;
}

namespace mdb::tc::ptrace {

struct RegisterCache
{
  Pid mTid{};
  user_regs_struct mUser{};

  bool Refresh() noexcept;
};

class Session final : public SupervisorState
{
  // Ptrace events that happens out of order with respect to task creation will be queued here.
  // So if a thread issues a clone system call and we receive the child's event first for some reason
  // we queue it here, and then pop it off once we handle the parent's ptrace event for clone/fork etc. That way we
  // don't have to create "unmanaged" TaskInfo objects which was error prone. We know the pid for the task here, so
  // it's easy to just look up.
  static std::vector<PtraceEvent> sUnhandledPtraceEvents;
  mdb::ScopedFd mProcFsMemFd;
  bool mIsVForking{ false };
  EventHandlerStack<StopStatus> mStopEventHandlerStack{};
  std::vector<StopStatus> mDeferredEvents{};
  std::unordered_map<Tid, RegisterCache> mRegisterCache{};

private:
  Session(Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept;

  void SetProgramCounterTo(TaskInfo &task, AddrPtr) noexcept;
  void OpenMemoryFile() noexcept;
  RegisterCache *GetUpToDateRegisterCache(Tid tid) noexcept;

  std::vector<Elf64_Phdr> LoadProgramHeaders(
    Pid pid, AddrPtr phdrAddress, size_t phdrCount, size_t phdrEntrySize) noexcept;

  /* Create new task meta data for `tid` */
  TaskInfo *CreateNewTask(Tid tid, std::optional<std::string_view> name, bool running) noexcept;
  void InitRegisterCacheFor(const TaskInfo &task) noexcept;

public:
  static Session *ForkExec(ui::dap::DebugAdapterManager *debugAdapterClient,
    bool stopAtEntry,
    const Path &program,
    std::span<std::pmr::string> prog_args,
    std::optional<BreakpointBehavior> breakpointBehavior) noexcept;

  static Session *Create(Tid taskLeader, ui::dap::DebugAdapterManager *dap) noexcept;
  static void QueueUnhandledPtraceEvent(PtraceEvent event) noexcept;
  void ProcessQueuedUnhandled(Pid childPid) noexcept;

  void HandleEvent(TaskInfo &task, StopStatus stopStatus) noexcept;
  void HandleEvent(TaskInfo &task, PtraceEvent event) noexcept;
  void QueuePending(StopStatus event) noexcept;
  void ProcessDeferredEvents() noexcept;

  bool ReadThreadName(Tid tid, std::string &result) noexcept;

  // Implementation specific interface
private:
  void HandleFork(TaskInfo &task, pid_t newChild, bool vFork) noexcept final;
  mdb::Expected<Auxv, Error> DoReadAuxiliaryVector() noexcept final;

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
  ReadResult DoReadBytes(AddrPtr address, u64 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult DoWriteBytes(AddrPtr addr, const u8 *buf, u64 size) noexcept final;

  // Install (new) software breakpoint at `addr`. The retuning TaskExecuteResponse *can* contain the original byte
  // that was overwritten if the current tracee interface needs it (which is the case for PtraceCommander)
  TaskExecuteResponse InstallBreakpoint(Tid tid, AddrPtr addr) noexcept final;
  TaskExecuteResponse EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  TaskExecuteResponse DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept final;
  // Can (possibly) modify state in `t`
  TaskExecuteResponse StopTask(TaskInfo &t) noexcept final;
  void DoResumeTask(TaskInfo &t, RunType type) noexcept final;
  bool DoResumeTarget(RunType type) noexcept final;
  bool Pause(Tid tid) noexcept final;
  bool CanContinue() noexcept final;
};

} // namespace mdb::tc::ptrace
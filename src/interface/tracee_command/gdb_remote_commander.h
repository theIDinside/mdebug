/** LICENSE TEMPLATE */
#pragma once

#include "interface/attach_args.h"
#include "interface/remotegdb/target_description.h"
#include "tracee_command_interface.h"
#include "utils/expected.h"
#include "utils/scoped_fd.h"
#include <interface/remotegdb/connection.h>
#include <link.h>

namespace mdb::tc {

using AuxvData = std::optional<std::string>;

class GdbRemoteCommander final : public TraceeCommandInterface
{
  std::shared_ptr<gdb::RemoteConnection> mConnection;
  gdb::WriteBuffer *mWriteBuffer = gdb::WriteBuffer::Create(16);
  Pid mProcessId;
  std::optional<std::string> mExecFile{};
  Auxv mAuxvData{};
  RemoteType mRemoteType;
  // TODO(simon): allow for smart caching of thread names, by catching system call `prctl` with the parameters that
  // call the `PR_SET_NAME` request, and on SyscallExit, call qXfer:threads:read:... and update the cache.
  // This way, we don't have to potentially open N files to /proc/<pid>/task/<tid> on every `Threads` request
  std::unordered_map<Tid, std::string> mThreadNames{};

  void SetCatchSyscalls(bool on) noexcept;
  void inform_supported() noexcept;

public:
  GdbRemoteCommander(RemoteType type, std::shared_ptr<gdb::RemoteConnection> conn, Pid process_id,
                     std::optional<std::string> execFile, std::shared_ptr<gdb::ArchictectureInfo> arch) noexcept;
  ~GdbRemoteCommander() noexcept override = default;

  ReadResult ReadBytes(AddrPtr address, u32 size, u8 *readBuffer) noexcept final;
  TraceeWriteResult WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse ReverseContinue(bool stepOnly) noexcept final;
  TaskExecuteResponse ResumeTask(TaskInfo &t, ResumeAction type) noexcept final;
  TaskExecuteResponse ResumeTarget(TraceeController *tc, ResumeAction run,
                                   std::vector<Tid> *resumedThreads = nullptr) noexcept final;
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

  TaskExecuteResponse Disconnect(bool terminate) noexcept final;
  bool PerformShutdown() noexcept final;

  bool OnExec() noexcept final;
  // Called after a fork for the creation of a new process supervisor
  Interface OnFork(Pid pid) noexcept final;
  bool PostFork(TraceeController *parent) noexcept final;
  bool IsAllStopSession() noexcept final;

  Tid TaskLeaderTid() const noexcept final;
  gdb::GdbThread LeaderToGdb() const noexcept;
  std::optional<Path> ExecedFile() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept final;
  mdb::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept final;

  gdb::RemoteSettings &remote_settings() noexcept;

  bool
  IsReplaySession() const noexcept final
  {
    return mRemoteType == RemoteType::RR;
  }
};

struct Thread
{
  Tid tid;
  std::string name;
};

struct ProcessInfo
{
  std::string exe;
  Pid pid;
  std::vector<Thread> threads;
  std::shared_ptr<gdb::ArchictectureInfo> arch;
};

struct RemoteProcess
{
  /** Threads we encounter when we attach to a remote process. */
  std::vector<Thread> threads;
  /** The newly created Tracee Command Interface for the remote process. */
  std::unique_ptr<GdbRemoteCommander> tc;
};
// Unlike PtraceCommander, which *is* initialized fully on construction, a remote session behaves and looks
// substantially different When a Ptrace session starts, we are making a ptrace(ATTACH, pid) - thus starting the
// session of 1 process. With a remote session, we may be connecting to a target which already have N sessions
// started. What this means is, we need to be able to turn "our" one "attach(HOST, PORT)" call, into returning N
// results of TraceeCommandInterface instead of just 1. This class facilitates that.
class RemoteSessionConfigurator
{
  gdb::RemoteConnection::ShrPtr conn = nullptr;

public:
  // First target
  explicit RemoteSessionConfigurator(gdb::RemoteConnection::ShrPtr remote) noexcept;
  mdb::Expected<std::vector<RemoteProcess>, gdb::ConnInitError> configure_session() noexcept;
  mdb::Expected<std::vector<RemoteProcess>, gdb::ConnInitError> configure_rr_session() noexcept;
};
} // namespace mdb::tc
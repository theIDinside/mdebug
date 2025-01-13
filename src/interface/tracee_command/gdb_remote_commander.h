/** LICENSE TEMPLATE */
#pragma once

#include "interface/attach_args.h"
#include "interface/remotegdb/target_description.h"
#include "tracee_command_interface.h"
#include "utils/expected.h"
#include "utils/scoped_fd.h"
#include <interface/remotegdb/connection.h>
#include <link.h>

namespace tc {

template <size_t N> struct CommandSerializer
{
  std::array<char, N> buffer;
  u32 pos{0};
  constexpr CommandSerializer() : buffer() {}

  template <size_t CStringArrSize>
  constexpr CommandSerializer(const char (&buf)[CStringArrSize]) : buffer({buf}), pos(CStringArrSize)
  {
  }

  constexpr void
  command(std::string_view v) noexcept
  {
    ASSERT(v.size() < N, "command name longer than buffer");
    std::copy(v.begin(), v.end(), buffer.begin());
    pos += v.size();
  }

  template <char Delimiter = ','>
  constexpr void
  write_address(AddrPtr addr) noexcept
  {
    buffer[pos++] = Delimiter;
    const auto res = std::to_chars(buffer.data() + pos, buffer.data() + N, addr.get(), 16);
    ASSERT(res.ec == std::errc(), "Expected succefull conversion of addr to string param");
    pos = static_cast<u32>(res.ptr - buffer.data());
  }

  template <char Delimiter = ','>
  constexpr void
  write_number_param(u32 number) noexcept
  {
    buffer[pos++] = Delimiter;
    const auto res = std::to_chars(buffer.data() + pos, buffer.data() + N, number, 16);
    ASSERT(res.ec == std::errc(), "Expected succefull conversion of addr to string param");
    pos = static_cast<u32>(res.ptr - buffer.data());
  }

  template <char Delimiter = ','>
  constexpr void
  write_char(char c) noexcept
  {
    buffer[pos++] = Delimiter;
    buffer[pos++] = c;
  }

  constexpr std::string_view
  serialize() const noexcept
  {
    return std::string_view{buffer.data(), buffer.data() + pos};
  }
};

using AuxvData = std::optional<std::string>;

class GdbRemoteCommander final : public TraceeCommandInterface
{
  std::shared_ptr<gdb::RemoteConnection> connection;
  Pid process_id;
  std::optional<std::string> exec_file{};
  Auxv auxv_data{};
  RemoteType type;
  // TODO(simon): allow for smart caching of thread names, by catching system call `prctl` with the parameters that
  // call the `PR_SET_NAME` request, and on SyscallExit, call qXfer:threads:read:... and update the cache.
  // This way, we don't have to potentially open N files to /proc/<pid>/task/<tid> on every `Threads` request
  std::unordered_map<Tid, std::string> thread_names{};

  void SetCatchSyscalls(bool on) noexcept;
  void inform_supported() noexcept;

public:
  GdbRemoteCommander(RemoteType type, std::shared_ptr<gdb::RemoteConnection> conn, Pid process_id,
                     std::string &&exec_file, std::shared_ptr<gdb::ArchictectureInfo> &&arch) noexcept;
  ~GdbRemoteCommander() noexcept override = default;

  ReadResult ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept final;
  TraceeWriteResult WriteBytes(AddrPtr addr, u8 *buf, u32 size) noexcept final;

  TaskExecuteResponse ReverseContinue() noexcept final;
  TaskExecuteResponse ResumeTask(TaskInfo &t, ResumeAction type) noexcept final;
  TaskExecuteResponse ResumeTarget(TraceeController *tc, ResumeAction run) noexcept final;
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
  bool Initialize() noexcept final;

  bool OnExec() noexcept final;
  // Called after a fork for the creation of a new process supervisor
  Interface OnFork(Pid pid) noexcept final;

  Tid TaskLeaderTid() const noexcept final;
  gdb::GdbThread leader_to_gdb() const noexcept;
  std::optional<Path> ExecedFile() noexcept final;
  std::optional<std::vector<ObjectFileDescriptor>> ReadLibraries() noexcept final;
  std::shared_ptr<gdb::RemoteConnection> RemoteConnection() noexcept final;
  utils::Expected<Auxv, Error> ReadAuxiliaryVector() noexcept final;

  gdb::RemoteSettings &remote_settings() noexcept;
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
  GdbRemoteCommander::OwnPtr tc;
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
  utils::Expected<std::vector<RemoteProcess>, gdb::ConnInitError> configure_session() noexcept;
  utils::Expected<std::vector<RemoteProcess>, gdb::ConnInitError> configure_rr_session() noexcept;
};
} // namespace tc
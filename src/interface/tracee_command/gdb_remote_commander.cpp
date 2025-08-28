/** LICENSE TEMPLATE */
#include "gdb_remote_commander.h"
#include "common.h"
#include "interface/attach_args.h"
#include "interface/remotegdb/deserialization.h"
#include "interface/remotegdb/shared.h"
#include "interface/remotegdb/target_description.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "utils/logger.h"
#include "utils/xml.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <set>
#include <supervisor.h>
#include <sys/user.h>
#include <tracer.h>

namespace mdb::tc {

// Commands that only return OK response, uses this
#define OkOtherwiseErr(cmd, errMsg)                                                                               \
  if (!conn->ExecuteCommand(cmd, 5000) || cmd.mResult.value_or("") != "$OK") {                                    \
    return ConnInitError{ .msg = errMsg };                                                                        \
  }

// For use with commands that responds with arbitrary data (i.e. doesn't contain an OK in the string data)
#define SuccessOtherwiseErr(cmd, errMsg)                                                                          \
  if (!conn->ExecuteCommand(cmd, 5000)) {                                                                         \
    return ConnInitError{ .msg = errMsg };                                                                        \
  }

template <typename T, typename U> using ViewOfParameter = U;

#define SerializeCommand(Buf, FmtStr, ...)                                                                        \
  [&Buf](auto &&...args) noexcept {                                                                               \
    auto it = std::format_to(Buf.begin(), FmtStr, args...);                                                       \
    return std::string_view{ Buf.begin(), it };                                                                   \
  }(__VA_ARGS__)

template <std::integral Value>
static std::string_view
convert_to_target(std::array<char, 16> &outbuf, Value value) noexcept
{
  constexpr auto TSize = sizeof(Value);
  std::array<u8, TSize> bytes{};
  std::memcpy(bytes.data(), &value, TSize);

  auto ptr = outbuf.data();
  for (const auto byte : bytes) {
    auto res = std::to_chars(ptr, ptr + 2, byte, 16);
    MDB_ASSERT(res.ec == std::errc(), "to_chars conversion failed");
    ptr = res.ptr;
  }
  return std::string_view{ outbuf.data(), ptr };
}

static std::vector<std::tuple<SessionId, Tid, std::string>>
parse_threads(std::string_view input) noexcept
{
  std::vector<std::tuple<SessionId, Tid, std::string>> result{};
  xml::XMLParser parser{ input };
  auto rootElement = parser.parse();
  result.reserve(rootElement->children.size());

  for (const auto &thread : rootElement->children) {
    if (const auto lwp = thread->attribute("id"); lwp) {
      std::string_view str = lwp.value();
      const auto [pid, tid] = gdb::GdbThread::parse_thread(str);
      result.emplace_back(pid, tid, thread->attribute("name").value_or("None"));
    }
  }
  return result;
}

template <size_t N>
static ViewOfParameter<char[], std::string_view>
append_checksum(char (&buf)[N], std::string_view payload)
{
  MDB_ASSERT(
    payload.size() < N, "Alotted buffer of size N={} too small to handle payload's size {}", N, payload.size());

  MDB_ASSERT(buf[1 + payload.size()] == '#',
    "Expected a packet end '#' at {} but found {}",
    1 + payload.size(),
    buf[1 + payload.size()]);

  auto [a, b] = gdb::checksum(std::string_view{ buf + 1, buf + 1 + payload.size() });
  buf[2 + payload.size()] = a;
  buf[3 + payload.size()] = a;
  // Be wary of life time issues here. But I know what I'm doing. The life time of the returned view is bound to
  // the life time of `buf`
  return std::string_view{ buf, buf + 3 + payload.size() };
}

GdbRemoteCommander::GdbRemoteCommander(RemoteType type,
  std::shared_ptr<gdb::RemoteConnection> conn,
  SessionId processId,
  std::optional<std::string> execFile,
  std::shared_ptr<gdb::ArchictectureInfo> arch) noexcept
    : TraceeCommandInterface(TargetFormat::Remote, std::move(arch), TraceeInterfaceType::GdbRemote),
      mConnection(std::move(conn)), mProcessId(processId), mExecFile(std::move(execFile)), mRemoteType(type)
{
}

static ReadResult
ToReadResult(const gdb::SendError &err) noexcept
{
  return std::visit(
    [](auto &err) noexcept -> ReadResult {
      using T = ActualType<decltype(err)>;
      // NAck
      if constexpr (std::is_same_v<T, gdb::SystemError>) {
        return ReadResult::SystemError(err.syserrno);
      } else if constexpr (std::is_same_v<T, gdb::Timeout>) {
        return ReadResult::SystemError(0);
      } else if constexpr (std::is_same_v<T, gdb::NAck>) {
        return ReadResult::SystemError(0);
      } else {
        static_assert(always_false<T>, "unhandled branch");
        return ReadResult::SystemError(0);
      }
    },
    err);
}

ReadResult
GdbRemoteCommander::ReadBytes(AddrPtr address, u32 size, u8 *readBuffer) noexcept
{
  std::array<char, 64> buf{};
  const auto cmd = SerializeCommand(buf, "m{:x},{}", address.GetRaw(), size);
  const auto pid = TaskLeaderTid();
  const auto res = mConnection->SendCommandWaitForResponse(gdb::GdbThread{ pid, pid }, cmd, 1000);
  if (res.is_error()) {
    return ToReadResult(res.error());
  }

  const auto &msg = res.value();
  std::string_view str{ msg };
  str.remove_prefix(1);
  auto ptr = readBuffer;
  auto decodeBuffer = mWriteBuffer->TakeSpan(size * 2);
  const auto len = gdb::DecodeRunLengthEncoding(str, decodeBuffer.data(), decodeBuffer.size_bytes());
  std::string_view decoded{ decodeBuffer.data(), len };
  MDB_ASSERT((decoded.size() & 0b1) == 0, "Expected buffer to be divisible by 2");
  while (!decoded.empty()) {
    *ptr = fromhex(decoded[0]) * 16 + fromhex(decoded[1]);
    ++ptr;
    decoded.remove_prefix(2);
  }
  // NOTA BENE: We actually return the *decoded* size of read bytes, not the actual read bytes from the remote.
  // That shit would make no sense, since this is represented by the TraceeCommand interface
  return ReadResult::Ok(ptr - readBuffer);
}
TraceeWriteResult
GdbRemoteCommander::WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  static constexpr std::array<char, 16> Table = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };
  std::string outbuf{};
  outbuf.reserve(size * 2);
  for (auto i = 0u; i < size; ++i) {
    const u8 val = *(buf + i);
    char hi = Table[((val & 0b1111'0000) >> 4)];
    char lo = Table[(val & 0b0000'1111)];
    outbuf.push_back(hi);
    outbuf.push_back(lo);
  }
  auto cmd = std::format("M{:x},{}:{}", addr.GetRaw(), size, outbuf);
  const auto res = mConnection->SendCommandWaitForResponse(LeaderToGdb(), cmd, 1000);
  if (res.is_error()) {
    return TraceeWriteResult::Error(0);
  }

  // TODO: gdb just errors out like a moron, if a partial write was successful
  // how? Who tf knows. The "protocol" sure leaves much to the imagination.
  if (res.value() == "$OK") {
    return TraceeWriteResult::Ok(size);
  }
  return TraceeWriteResult::Error(0);
}

void
GdbRemoteCommander::SetCatchSyscalls(bool on) noexcept
{
  const bool catch_syscall = mConnection->GetSettings().mCatchSyscalls;
  if (on && !catch_syscall) {
    const auto response = mConnection->SendCommandWaitForResponse(LeaderToGdb(), "QCatchSyscalls:1", {});
    if (response.is_error()) {
      PANIC("failed to set catch syscalls");
    }
    MDB_ASSERT(response.value() == "OK", "Response for command was not 'OK'");
  } else if (!on && catch_syscall) {
    const auto response = mConnection->SendCommandWaitForResponse(LeaderToGdb(), "QCatchSyscalls:0", {});
    if (response.is_error()) {
      PANIC("failed to set catch syscalls");
    }
    MDB_ASSERT(response.value() == "OK", "Response for command was not 'OK'");
  }

  mConnection->GetSettings().mCatchSyscalls = on;
}

TaskExecuteResponse
GdbRemoteCommander::ResumeTask(TaskInfo &t, ResumeAction action) noexcept
{
  SetCatchSyscalls(action.mResumeType == RunType::SyscallContinue);

  const auto pid = TaskLeaderTid();
  std::array<char, 128> buf{};
  std::string_view resumeCommand;
  if (action.mDeliverSignal == -1) {
    action.mDeliverSignal = t.mLastWaitStatus.signal == SIGTRAP ? 0 : t.mLastWaitStatus.signal;
  }
  switch (action.mResumeType) {
  case RunType::Step: {
    if (action.mDeliverSignal == 0) {
      resumeCommand = SerializeCommand(buf, "vCont;s:p{:x}.{:x}", pid, t.mTid);
    } else {
      resumeCommand = SerializeCommand(buf, "vCont;S{:02x}:p{:x}.{:x}", action.mDeliverSignal, pid, t.mTid);
    }
    break;
  }
  case RunType::Continue:
  case RunType::SyscallContinue: {
    if (action.mDeliverSignal == 0) {
      resumeCommand = SerializeCommand(buf, "vCont;c:p{:x}.{:x}", pid, t.mTid);
    } else {
      resumeCommand = SerializeCommand(buf, "vCont;C{:02x}:p{:x}.{:x}", action.mDeliverSignal, pid, t.mTid);
    }
  } break;
  case RunType::Unknown:
    PANIC("Unknown resume action");
  }

  const auto resumeError = mConnection->SendVContCommand(resumeCommand, {});
  MDB_ASSERT(!resumeError.has_value(), "vCont resume command failed");
  t.SetCurrentResumeAction(action);
  mConnection->InvalidateKnownThreads();
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::ReverseContinue(bool stepOnly) noexcept
{
  if (mRemoteType != RemoteType::RR) {
    return TaskExecuteResponse::Error(0);
  }

  auto reverse = stepOnly ? "bs" : "bc";
  const auto resumeError = mConnection->SendVContCommand(reverse, 1000);
  MDB_ASSERT(!resumeError.has_value(), "reverse continue failed");

  for (auto &entry : mControl->GetThreads()) {
    entry.mTask->SetCurrentResumeAction({ .mResumeType = RunType::Continue,
      .mResumeTarget = ResumeTarget::AllNonRunningInProcess,
      .mDeliverSignal = 0 });
  }
  mConnection->InvalidateKnownThreads();
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::ResumeTarget(TraceeController *tc, ResumeAction action, std::vector<Tid> *) noexcept
{
  // TODO: implement writing the resumed threads into `resumedThreads` if it's not null.
  SetCatchSyscalls(action.mResumeType == RunType::SyscallContinue);

  if (action.mDeliverSignal == -1) {
    action.mDeliverSignal = 0;
  }

  for (auto &entry : tc->GetThreads()) {
    if (entry.mTask->mBreakpointLocationStatus.IsValid()) {
      entry.mTask->StepOverBreakpoint(tc, action.mResumeType);
      if (!mConnection->GetSettings().mIsNonStop) {
        return TaskExecuteResponse::Ok();
      }
    }
  }

  const auto pid = TaskLeaderTid();
  std::array<char, 128> buf{};
  std::string_view resumecommand;
  switch (action.mResumeType) {
  case RunType::Step: {
    if (action.mDeliverSignal == 0) {
      resumecommand = SerializeCommand(buf, "vCont;s:p{:x}.-1", pid);
    } else {
      resumecommand = SerializeCommand(buf, "vCont;S{:02x}:p{:x}.-1", action.mDeliverSignal, pid);
    }
    break;
  }
  case RunType::Continue:
  case RunType::SyscallContinue: {
    if (action.mDeliverSignal == 0) {
      resumecommand = SerializeCommand(buf, "vCont;c:p{:x}.-1", pid);
    } else {
      resumecommand = SerializeCommand(buf, "vCont;C{:02x}:p{:x}.-1", action.mDeliverSignal, pid);
    }
  } break;
  case RunType::Unknown:
    PANIC("unknown resume type");
  }

  const auto resumeError = mConnection->SendVContCommand(resumecommand, {});
  MDB_ASSERT(!resumeError.has_value(), "vCont resume command failed");
  for (auto &entry : tc->GetThreads()) {
    entry.mTask->SetCurrentResumeAction(action);
  }
  mConnection->InvalidateKnownThreads();
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::StopTask(TaskInfo &t) noexcept
{
  if (remote_settings().mIsNonStop) {
    std::array<char, 64> bytes{};
    const auto pid = TaskLeaderTid();
    auto cmd = SerializeCommand(bytes, "vCont;t:p{}.{}", pid, t.mTid);
    auto response = mConnection->SendCommandWaitForResponse(LeaderToGdb(), cmd, 1000);
    if (!(response.is_expected() && response.take_value() == "$OK")) {
      PANIC("Failed to unset breakpoint");
    }
    return TaskExecuteResponse::Ok();
  } else {
    // std::array<char, 64> bytes{};
    // auto cmd = SerializeCommand(bytes, "vCtrlC");
    // auto response = connection->send_command_with_response(cmd, 1000);
    // if (!(response.is_expected() && response.take_value() == "$OK")) {
    //   PANIC("Failed to unset breakpoint");
    // }
    mConnection->SendInterruptByte();
    return TaskExecuteResponse::Ok();
  }
}

TaskExecuteResponse
GdbRemoteCommander::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  return InstallBreakpoint(tid, location.Address());
}

TaskExecuteResponse
GdbRemoteCommander::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  std::array<char, 32> bytes{};
  auto cmd = SerializeCommand(bytes, "z0,{:x},1", location.Address().GetRaw());
  auto response = mConnection->SendCommandWaitForResponse(gdb::GdbThread{ mProcessId, tid }, cmd, 1000);
  if (!(response.is_expected() && response.take_value() == "$OK")) {
    PANIC("Failed to unset breakpoint");
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::InstallBreakpoint(Tid tid, AddrPtr addr) noexcept
{
  std::array<char, 32> bytes{};
  auto cmd = SerializeCommand(bytes, "Z0,{:x},1", addr.GetRaw());

  auto res = mConnection->SendCommandWaitForResponse(gdb::GdbThread{ mProcessId, tid }, cmd, 1000);
  if (res.is_error()) {
    return TaskExecuteResponse::Error(0);
  }
  if (res.take_value() != "$OK") {
    return TaskExecuteResponse::Error(0);
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
GdbRemoteCommander::ReadRegisters(TaskInfo &t) noexcept
{
  const gdb::GdbThread thread{ TaskLeaderTid(), t.mTid };
  auto result = mConnection->SendCommandWaitForResponse(thread, "g", 1000);
  if (result.is_error()) {
    return TaskExecuteResponse::Error(0);
  }

  auto register_contents = result.take_value();
  DBGLOG(remote, "Read register field for {}: {}", t.mTid, register_contents);

  std::string_view payload{ register_contents };

  MDB_ASSERT(payload.front() == '$', "Expected OK response");
  payload.remove_prefix(1);

  t.RemoteFromHexdigitEncoding(payload);

  return TaskExecuteResponse::Ok(register_contents.size());
}
TaskExecuteResponse
GdbRemoteCommander::WriteRegisters(const user_regs_struct &input) noexcept
{
  (void)input;
  TODO("Implement");
}

TaskExecuteResponse
GdbRemoteCommander::SetProgramCounter(const TaskInfo &t, AddrPtr addr) noexcept
{
  std::array<char, 64> setThreadBytes{};
  std::array<char, 64> setPcBytes{};
  std::array<char, 16> registerContents{};
  auto register_value = convert_to_target(registerContents, addr.GetRaw());
  auto cmds = std::to_array({ SerializeCommand(setThreadBytes, "Hgp{:x}.{:x}", TaskLeaderTid(), t.mTid),
    SerializeCommand(
      setPcBytes, "P{:x}={}", mArchInfo->mDebugContextRegisters->mRIPNumber.Cast(), register_value) });
  auto response = mConnection->SendInOrderCommandChain(cmds, 1000);
  if (response.is_error()) {
    DBGLOG(remote, "Failed to set pc");
    return TaskExecuteResponse::Error(0);
  }
  auto responses = response.take_value();
  auto i = 0;
  for (const auto &r : responses) {
    if (r != "$OK") {
      DBGLOG(remote, "Response for {} was not OK: {}", cmds[i], r);
      return TaskExecuteResponse::Error(0);
    }
    ++i;
  }
  t.RemoteX86Registers()->SetPc(addr);
  return TaskExecuteResponse::Ok(0);
}

std::string_view
GdbRemoteCommander::GetThreadName(Tid tid) noexcept
{
  switch (mRemoteType) {
  case RemoteType::RR: {
    char buf[256];
    auto end = std::format_to(buf, "qThreadExtraInfo,p{:x}.{:x}", TaskLeaderTid(), tid);
    std::string_view cmd{ buf, end };
    const auto res = mConnection->SendCommandWaitForResponse(LeaderToGdb(), cmd, 1000);
    if (res.is_expected()) {
      auto &name = mThreadNames[tid];
      name.clear();
      std::string_view n{ res.value() };
      n.remove_prefix("$"sv.size());
      name.reserve(n.size() / 2);
      for (auto i = 0u; i < n.size(); i += 2) {
        char ch = fromhex(n[i]) << 4 | fromhex(n[i + 1]);
        if (ch == 0) {
          break;
        }
        name.push_back(ch);
      }
    } else {
      mThreadNames[tid] = "Unknown";
    }
    return mThreadNames[tid];
  }
  case RemoteType::GDB: {
    // TODO(Implement name change)
    if (auto opt = mdb::find_if(mThreadNames, [tid](auto &kvp) { return kvp.first == tid; }); opt) {
      return (*opt)->second;
    }
    // READ ALL THREADS THAT REMOTE IS ATTACHED TO

    gdb::qXferCommand readThreads{ "qXfer:threads:read:", 0x8000 };
    const auto ok = mConnection->SendQXferCommandWithResponse(readThreads, 1000);
    if (!ok) {
      return "";
    }

    for (auto &&[pid, tid, name] : parse_threads(readThreads.mResponseBuffer)) {
      mThreadNames.emplace(tid, std::move(name));
    }
    return mThreadNames[tid];
  }
  }
  NEVER("Unknown remote type");
}

TaskExecuteResponse
GdbRemoteCommander::Disconnect(bool terminate) noexcept
{
  std::array<char, 64> buf{};
  if (terminate) {
    auto cmd = SerializeCommand(buf, "vKill;{}", TaskLeaderTid());
    const auto res = mConnection->SendCommandWaitForResponse({}, cmd, 1000);
    if (res.is_expected() && res.value() == "$OK"sv) {
      return TaskExecuteResponse::Ok();
    }
    return TaskExecuteResponse::Error(0);
  } else {
    auto cmd = SerializeCommand(buf, "D;{}", TaskLeaderTid());
    const auto res = mConnection->SendCommandWaitForResponse({}, cmd, 1000);
    if (res.is_expected() && res.value() == "$OK"sv) {
      return TaskExecuteResponse::Ok();
    }
    return TaskExecuteResponse::Error(0);
  }
}
bool
GdbRemoteCommander::PerformShutdown() noexcept
{
  DBGLOG(core, "Perform shut down for GdbRemote Commander - not sure anything's really needed here?");
  return true;
}

bool
GdbRemoteCommander::OnExec() noexcept
{
  auto auxv = ReadAuxiliaryVector();
  MDB_ASSERT(auxv.is_expected(), "Failed to read auxiliary vector");
  GetSupervisor()->SetAuxiliaryVector(ParsedAuxiliaryVectorData(auxv.take_value()));

  if (auto symbol_obj = Tracer::Get().LookupSymbolfile(*mExecFile); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(mControl, *mExecFile);
    if (obj->GetElf()->AddressesNeedsRelocation()) {
      mControl->RegisterObjectFile(mControl, std::move(obj), true, mControl->EntryAddress());
    } else {
      mControl->RegisterObjectFile(mControl, std::move(obj), true, nullptr);
    }
  } else {
    mControl->RegisterSymbolFile(symbol_obj, true);
  }

  tracee_r_debug = GetSupervisor()->InstallDynamicLoaderBreakpoints();
  std::vector<std::shared_ptr<SymbolFile>>{ mControl->GetSymbolFiles().begin(), mControl->GetSymbolFiles().end() };
  mControl->DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>>{
    mControl->GetSymbolFiles().begin(), mControl->GetSymbolFiles().end() });
  return true;
}

Interface
GdbRemoteCommander::OnFork(SessionId newProcess) noexcept
{
  // RemoteType type, std::shared_ptr<gdb::RemoteConnection> conn, Pid process_id, std::string &&exec_file,
  // std::shared_ptr<gdb::ArchictectureInfo> &&arch
  auto arch = mArchInfo;
  auto execFile = mExecFile;
  return std::make_unique<GdbRemoteCommander>(
    mRemoteType, mConnection, newProcess, std::move(execFile), std::move(arch));
}

bool
GdbRemoteCommander::PostFork(TraceeController *) noexcept
{
  // RR manages process creation entirely (more or less). It doesn't just copy
  // address space willy nilly. Therefore we need to actually install
  // breakpoints for the newly forked process, because they don't follow like
  // they would during a ptrace session of a fork.
  return mRemoteType != RemoteType::RR;
}

bool
GdbRemoteCommander::IsAllStopSession() noexcept
{
  // TODO: Add support for configurable "all stop sessions" for gdb remotes. For now it's entirely uninteresting.
  // We're aiming for RR-first support then we can start caring about a broader gdb remote support.
  return mRemoteType == RemoteType::RR;
}

std::optional<Path>
GdbRemoteCommander::ExecedFile() noexcept
{
  if (mExecFile) {
    return mExecFile.transform([](auto &p) { return Path{ p }; });
  } else {
    char buf[10]{ 0 };
    auto ptr = gdb::FormatValue(buf, mProcessId);
    gdb::qXferCommand execfile{ "qXfer:exec-file:read:", 0x1000, std::string_view{ buf, ptr } };
    const auto result = mConnection->SendQXferCommandWithResponse(execfile, 1000);
    if (!result) {
      return {};
    } else {
      mExecFile = execfile.mResponseBuffer;
    }
  }
  return mExecFile;
}

Tid
GdbRemoteCommander::TaskLeaderTid() const noexcept
{
  return mProcessId;
}

gdb::GdbThread
GdbRemoteCommander::LeaderToGdb() const noexcept
{
  return gdb::GdbThread{ mProcessId, mProcessId };
}

std::optional<std::vector<ObjectFileDescriptor>>
GdbRemoteCommander::ReadLibraries() noexcept
{
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  auto rdebug_ext_res = ReadType(tracee_r_debug);
  if (rdebug_ext_res.is_error()) {
    DBGLOG(core, "Could not read rdebug_extended");
    return {};
  }
  r_debug_extended rdebug_ext = rdebug_ext_res.take_value();
  std::vector<ObjectFileDescriptor> obj_files{};
  // TODO(simon): Make this asynchronous; so that instead of creating a symbol file inside the loop
  //  instead make a function that returns a promise of a symbol file. That promise gets added to a std::vector on
  //  each loop and then when the while loop has finished, we wait on all promises, collecting them.
  while (true) {
    // means we've hit some "entry" point in the linker-debugger interface; we need to wait for RT_CONSISTENT to
    // safely read "link map" containing the shared objects
    if (rdebug_ext.base.r_state != rdebug_ext.base.RT_CONSISTENT) {
      if (obj_files.empty()) {
        DBGLOG(core, "Debug state not consistent: no information about obj files read");
        return {};
      } else {
        return obj_files;
      }
    }
    auto linkmap = TPtr<link_map>{ rdebug_ext.base.r_map };
    while (linkmap != nullptr) {
      auto map_res = ReadType(linkmap);
      if (!map_res.is_expected()) {
        DBGLOG(core, "Failed to read linkmap");
        return {};
      }
      auto map = map_res.take_value();
      auto name_ptr = TPtr<char>{ map.l_name };
      const auto path = ReadNullTerminatedString(name_ptr);
      if (!path) {
        DBGLOG(core, "Failed to read null-terminated string from tracee at {}", name_ptr);
      } else {
        obj_files.emplace_back(path.value(), map.l_addr);
      }
      linkmap = TPtr<link_map>{ map.l_next };
    }
    const auto next = TPtr<r_debug_extended>{ rdebug_ext.r_next };
    if (next != nullptr) {
      const auto next_rdebug = ReadType(next);
      if (next_rdebug.is_error()) {
        break;
      } else {
        rdebug_ext = next_rdebug.value();
      }
    } else {
      break;
    }
  }

  return obj_files;
}

std::shared_ptr<gdb::RemoteConnection>
GdbRemoteCommander::RemoteConnection() noexcept
{
  return mConnection;
}

mdb::Expected<Auxv, Error>
GdbRemoteCommander::ReadAuxiliaryVector() noexcept
{
  static constexpr auto BufSize = PAGE_SIZE;
  if (!mAuxvData.mContents.empty()) {
    return mdb::expected(std::move(mAuxvData));
  } else {
    std::array<char, 64> bytes{};
    auto cmd = SerializeCommand(bytes, "Hgp{:x}.{:x}", TaskLeaderTid(), TaskLeaderTid());
    auto set_thread = mConnection->SendCommandWaitForResponse(LeaderToGdb(), cmd, 1000);

    gdb::qXferCommand readAuxvCommand{ "qXfer:auxv:read:", 0x1000 };
    const auto result = mConnection->SendQXferCommandWithResponse(readAuxvCommand, 1000);
    if (!result) {
      return Error{ .mSysErrorNumber = {}, .mErrorMessage = "qXfer command failed" };
    }
    auto buf = std::make_unique<char[]>(BufSize);
    auto d = gdb::DecodeRunLengthEncToStringView(readAuxvCommand.mResponseBuffer, buf.get(), BufSize);
    tc::Auxv aux;
    while (d.size() >= 16) {
      u64 k{ 0 };
      std::memcpy(&k, d.data(), 8);
      d.remove_prefix(8);
      u64 v{ 0 };
      std::memcpy(&v, d.data(), 8);
      aux.mContents.push_back({ k, v });
      d.remove_prefix(8);
    }
    mAuxvData = aux;
    return aux;
  }
}

gdb::RemoteSettings &
GdbRemoteCommander::remote_settings() noexcept
{
  return mConnection->GetSettings();
}

RemoteSessionConfigurator::RemoteSessionConfigurator(gdb::RemoteConnection::ShrPtr remote) noexcept
    : conn(std::move(remote))
{
}

mdb::Expected<std::vector<RemoteProcess>, gdb::ConnInitError>
RemoteSessionConfigurator::configure_rr_session() noexcept
{
  using gdb::ConnInitError, gdb::SocketCommand;
  // Todo; make response buffers in this scope all tied to one allocation instead of multiple

  sleep(1);
  if (conn->GetSettings().mIsNoAck) {
    SocketCommand noack{ "QStartNoAckMode" };
    OkOtherwiseErr(noack, "Failed to configure no ack for connection");
  }
  // TURN ON EXTENDED MODE
  SocketCommand extended{ "!" };
  OkOtherwiseErr(extended, "Failed to configure extended mode");

  // INFORM REMOTE OF OUR CAPABILITIES; IT WILL RESPOND WITH THEIRS
  SocketCommand qSupported{
    "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;"
    "vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;QNonStop+"
  };
  SuccessOtherwiseErr(qSupported, "Failed to request supported options");
  conn->ParseSupported(qSupported.mResult.value());

  // READ ALL THREADS THAT REMOTE IS ATTACHED TO
  SocketCommand readThreads{ "qfThreadInfo" };
  SuccessOtherwiseErr(readThreads, "Failed to read threads list");
  std::vector<std::tuple<SessionId, Tid, std::string>> threads{};
  std::string_view threadsResult{ readThreads.mResult.value() };
  threadsResult.remove_prefix("$m"sv.size());
  const auto parsed = gdb::ProtocolParseThreads(threadsResult);
  threads.reserve(parsed.size());
  for (auto [pid, tid] : parsed) {
    threads.emplace_back(pid, tid, "");
  }
  for (;;) {
    SocketCommand continueReadThreads{ "qsThreadInfo" };
    SuccessOtherwiseErr(continueReadThreads, "Failed to continue thread query sequence");
    std::string_view res{ continueReadThreads.mResult.value() };
    if (res == "$l") {
      break;
    } else {
      res.remove_prefix("$m"sv.size());
      const auto parsed = gdb::ProtocolParseThreads(res);
      for (auto [pid, tid] : parsed) {
        threads.emplace_back(pid, tid, "");
      }
    }
  }

  std::vector<ProcessInfo> pinfo{};

  for (auto &&[pid, tid, name] : threads) {
    auto it = std::ranges::find_if(pinfo, [&](const auto &p) { return p.pid == pid; });
    if (it != std::end(pinfo)) {
      it->threads.push_back({ tid, std::move(name) });
    } else {
      char buf[10]{ 0 };
      auto ptr = gdb::FormatValue(buf, pid);
      gdb::qXferCommand execfile{ "qXfer:exec-file:read:", 0x1000, std::string_view{ buf, ptr } };
      if (!conn->ExecuteCommand(execfile, 0, 1000)) {
        return ConnInitError{ .msg = "Failed to get exec file of process" };
      }

      // Gdb does this before requesting target.xml - maybe this is yet another retarded thing about this *SO
      // CALLED* protocol.
      std::array<char, 32> select_thread{};
      auto cmd = SerializeCommand(select_thread, "Hgp{:x}.{:x}", pid, tid);
      SocketCommand selectThreadCommand{ cmd };
      OkOtherwiseErr(selectThreadCommand, "Failed to select thread for operation");

      gdb::qXferCommand requestArchInfo{ "qXfer:features:read:", 0x1000, "target.xml" };
      if (!conn->ExecuteCommand(requestArchInfo, 0, 1000)) {
        return ConnInitError{ .msg = "Failed to get exec file of process" };
      }

      DBGLOG(core, "Target Architecture Description requested:\n{}", requestArchInfo.mResponseBuffer);

      xml::XMLParser parser{ requestArchInfo.mResponseBuffer };
      auto rootElement = parser.parse();
      std::vector<gdb::ArchReg> completeArch{};
      auto registerNumber = 0;
      for (const auto &child : rootElement->children) {
        if (child->name == "xi:include") {
          const auto include = child->attribute("href");
          MDB_ASSERT(include.has_value(), "Expected xi:include to have href attribute");
          gdb::qXferCommand included{ "qXfer:features:read:", 0x1000, include.value() };
          if (!conn->ExecuteCommand(included, 0, 1000)) {
            return ConnInitError{ .msg = "Failed to get exec file of process" };
          }
          xml::XMLParser parser{ included.mResponseBuffer };
          auto include_root_element = parser.parse();
          auto arch = gdb::read_arch_info(include_root_element, &registerNumber);
          std::copy(arch.begin(), arch.end(), std::back_inserter(completeArch));
        }
      }

      std::sort(completeArch.begin(), completeArch.end(), [](auto &a, auto &b) { return a.regnum < b.regnum; });

      // Notice that we do not add the "main thread" to the list of threads. Because meta data for that thread
      // is created when we spawn the TraceeController supervisor struct (it creates a normal thread meta data
      // struct for the process)
      ;
      pinfo.push_back({ execfile.mResponseBuffer, pid, {}, gdb::ArchictectureInfo::CreateArchInfo(completeArch) });
    }
  }

  // PROCESS STOP REPLIES - THEY WILL GET SENT TO MAIN EVENT LOOP, ESSENTIALLY "STARTING" the session
  if (!threads.empty()) {
    if (auto err = conn->InitStopQuery(); err) {
      return err.value();
    }
  }

  std::vector<RemoteProcess> result{};
  result.reserve(pinfo.size());

  for (auto &&proc : pinfo) {
    result.emplace_back(std::move(proc.threads),
      std::make_unique<GdbRemoteCommander>(
        RemoteType::RR, conn, proc.pid, std::move(proc.exe), std::move(proc.arch)));
  }

  if (result.empty()) {
    return result;
  }

  conn->InitializeThread();
  return result;
}

mdb::Expected<std::vector<RemoteProcess>, gdb::ConnInitError>
RemoteSessionConfigurator::configure_session() noexcept
{
  using gdb::ConnInitError, gdb::SocketCommand;
  // Todo; make response buffers in this scope all tied to one allocation instead of multiple

  if (conn->GetSettings().mIsNoAck) {
    SocketCommand noack{ "QStartNoAckMode" };
    OkOtherwiseErr(noack, "Failed to configure no ack for connection");
  }
  // TURN ON EXTENDED MODE
  SocketCommand extended{ "!" };
  OkOtherwiseErr(extended, "Failed to configure extended mode");

  // INFORM REMOTE OF OUR CAPABILITIES; IT WILL RESPOND WITH THEIRS
  SocketCommand qSupported{
    "qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;"
    "vContSupported+;QThreadEvents+;QThreadOptions+;no-resumed+;memory-tagging+;xmlRegisters=i386;QNonStop+;;"
    "qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+"
  };
  SuccessOtherwiseErr(qSupported, "Failed to request supported options");
  conn->ParseSupported(qSupported.mResult.value());

  SocketCommand enableThreadEvents{ "QThreadEvents:1" };
  OkOtherwiseErr(enableThreadEvents, "Failed to set ThreadEvents to ON");

  // IF WE HAVE CFG = NON STOP, REQUEST TO SET IT
  if (conn->GetSettings().mIsNonStop) {
    SocketCommand setNonStop{ "QNonStop:1" };
    OkOtherwiseErr(setNonStop, "Failed to set non-stop mode");
  }

  // READ ALL THREADS THAT REMOTE IS ATTACHED TO
  gdb::qXferCommand readThreads{ "qXfer:threads:read:", 0x8000 };
  if (!conn->ExecuteCommand(readThreads, 0, 1000)) {
    return ConnInitError{ .msg = "Failed to determine what processes we are attached to" };
  }

  // DETERMINE WHAT PROCESS SPACES WE ARE ATTACHED TO
  const auto threads = parse_threads(readThreads.mResponseBuffer);

  std::vector<ProcessInfo> pinfo{};

  for (auto &&[pid, tid, name] : threads) {
    auto it = std::ranges::find_if(pinfo, [&](const auto &p) { return p.pid == pid; });
    if (it != std::end(pinfo)) {
      it->threads.push_back({ tid, name });
    } else {
      char buf[10]{ 0 };
      auto ptr = gdb::FormatValue(buf, pid);
      gdb::qXferCommand execfile{ "qXfer:exec-file:read:", 0x1000, std::string_view{ buf, ptr } };
      if (!conn->ExecuteCommand(execfile, 0, 1000)) {
        return ConnInitError{ .msg = "Failed to get exec file of process" };
      }

      // Gdb does this before requesting target.xml - maybe this is yet another retarded thing about this *SO
      // CALLED* protocol.
      std::array<char, 32> selectThread{};
      auto cmd = SerializeCommand(selectThread, "Hgp{:x}.{:x}", pid, tid);
      SocketCommand selectThreadCommand{ cmd };
      OkOtherwiseErr(selectThreadCommand, "Failed to select thread for operation");

      gdb::qXferCommand requestArchInfo{ "qXfer:features:read:", 0x1000, "target.xml" };
      if (!conn->ExecuteCommand(requestArchInfo, 0, 1000)) {
        return ConnInitError{ .msg = "Failed to get exec file of process" };
      }

      DBGLOG(core, "Target Architecture Description requested:\n{}", requestArchInfo.mResponseBuffer);

      xml::XMLParser parser{ requestArchInfo.mResponseBuffer };
      auto rootElement = parser.parse();
      auto registerNumber = 0;
      auto arch = gdb::read_arch_info(rootElement, &registerNumber);

      // Notice that we do not add the "main thread" to the list of threads. Because meta data for that thread
      // is created when we spawn the TraceeController supervisor struct (it creates a normal thread meta data
      // struct for the process)

      pinfo.push_back({ execfile.mResponseBuffer, pid, {}, gdb::ArchictectureInfo::CreateArchInfo(arch) });
    }
  }

  // PROCESS STOP REPLIES - THEY WILL GET SENT TO MAIN EVENT LOOP, ESSENTIALLY "STARTING" the session
  if (!threads.empty()) {
    if (auto err = conn->InitStopQuery(); err) {
      return err.value();
    }
  }

  std::vector<RemoteProcess> result{};
  result.reserve(pinfo.size());

  for (auto &&proc : pinfo) {
    result.emplace_back(std::move(proc.threads),
      std::make_unique<GdbRemoteCommander>(
        RemoteType::GDB, conn, proc.pid, std::move(proc.exe), std::move(proc.arch)));
  }

  if (result.empty()) {
    return result;
  }
  conn->InitializeThread();
  return result;
}

} // namespace mdb::tc

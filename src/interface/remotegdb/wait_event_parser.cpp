/** LICENSE TEMPLATE */
#include "wait_event_parser.h"
#include "bp.h"
#include "interface/remotegdb/connection.h"
#include "interface/remotegdb/shared.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include <charconv>
#include <event_queue.h>
#include <supervisor.h>
#include <tracer.h>

namespace mdb::gdb {

WaitEventParser::WaitEventParser(RemoteConnection &conn) noexcept : mConnection(conn) {}

EventDataParam
WaitEventParser::Params() const noexcept
{
  std::optional<int> eventTime = mEventTime > 0 ? std::nullopt : std::optional{mEventTime};
  return EventDataParam{.target = mPid, .tid = mTid, .sig_or_code = mSignal, .event_time = eventTime};
}

static std::string
DecodeHexString(std::string_view hexString)
{
  std::string result{};
  result.reserve(hexString.size() / 2);
  const auto end = hexString.end();
  for (auto it = hexString.begin(); it != end; it += 2) {
    char character = 0;
    const auto res = std::from_chars(it, it + 2, character, 16);
    ASSERT(res.ec == std::errc(), "Failed to convert hexstring char bytes to char");
    result.push_back(character);
  }
  return result;
}

void
WaitEventParser::ParseStopReason(TraceeStopReason reason, std::string_view val) noexcept
{
  SetStopReason(reason);
  switch (reason) {
  case TraceeStopReason::Watch:
  case TraceeStopReason::RWatch:
  case TraceeStopReason::AWatch: {
    const auto addr = ToAddress(val);
    ASSERT(addr, "Failed to parse address for remote stub watchpoint event from: '{}'", val);
    SetWatchpointAddress(addr.value());
    break;
  }
  case TraceeStopReason::SyscallEntry: {
    const auto sysnum = RemoteConnection::ParseHexDigits(val);
    SetSyscallEntry(*sysnum);
    break;
  }
  case TraceeStopReason::SyscallReturn: {
    const auto sysnum = RemoteConnection::ParseHexDigits(val);
    SetSyscallExit(*sysnum);
    break;
  }
  case TraceeStopReason::Library:
  case TraceeStopReason::ReplayLog:
  case TraceeStopReason::SWBreak:
  case TraceeStopReason::HWBreak:
    break;
  case TraceeStopReason::Fork: {
    ParseFork(val);
  } break;
  case TraceeStopReason::VFork: {
    ParseVFork(val);
  } break;
  case TraceeStopReason::VForkDone: {
  } break;
  case TraceeStopReason::Exec:
    SetExeced(val);
    break;
  case TraceeStopReason::Clone: {
    ParseClone(val);
  } break;
  case TraceeStopReason::Create:
    break;
  }
}

bool
WaitEventParser::IsStopReason(u32 maybeStopReason) noexcept
{
  return std::find(StopReasonTokens.begin(), StopReasonTokens.end(), maybeStopReason) !=
         std::end(StopReasonTokens);
}

void
WaitEventParser::ParsePidTid(std::string_view arg) noexcept
{
  const auto [pid, tid] = gdb::GdbThread::parse_thread(arg);
  SetPid(pid);
  SetTid(tid);
}

void
WaitEventParser::ParseCore(std::string_view arg) noexcept
{
  ASSERT(mCore == 0, "core has already been set");
  u32 parsedCore{0};
  auto parse = std::from_chars(arg.data(), arg.data() + arg.size(), parsedCore, 16);
  if (parse.ec != std::errc()) {
    PANIC("Failed to parse core");
  }
  mCore = parsedCore;
}

// Determines PC value, from the payload sent by the remote. Returns nullopt if no PC was provided (or we
// couldn't parse it)
std::optional<std::uintptr_t>
WaitEventParser::DeterminePc() const noexcept
{
  for (const auto &[no, reg] : mRegisters) {
    if (no == mArch.regs.rip_number) {
      u64 v;
      std::memcpy(&v, reg.data(), sizeof(v));
      return v;
    }
  }
  return {};
}

TraceEvent *
WaitEventParser::NewDebuggerEvent(bool init) noexcept
{
  if (mStopReason) {
    switch (*mStopReason) {
    case TraceeStopReason::Watch:
      return TraceEvent::CreateWriteWatchpoint(Params(), mWatchpointAddress, std::move(mRegisters));
    case TraceeStopReason::RWatch:
      return TraceEvent::CreateReadWatchpoint(Params(), mWatchpointAddress, std::move(mRegisters));
    case TraceeStopReason::AWatch:
      return TraceEvent::CreateAccessWatchpoint(Params(), mWatchpointAddress, std::move(mRegisters));
    case TraceeStopReason::SyscallEntry:
      return TraceEvent::CreateSyscallEntry(Params(), mSyscallNumber, std::move(mRegisters));
    case TraceeStopReason::SyscallReturn:
      return TraceEvent::CreateSyscallExit(Params(), mSyscallNumber, std::move(mRegisters));
    case TraceeStopReason::Library:
      return TraceEvent::CreateLibraryEvent(Params(), std::move(mRegisters));
    case TraceeStopReason::ReplayLog:
      TODO("Implement TraceeStopReason::ReplayLog");
    case TraceeStopReason::SWBreak: {
      return TraceEvent::CreateSoftwareBreakpointHit(Params(), DeterminePc(), std::move(mRegisters));
    }
    case TraceeStopReason::HWBreak: {
      return TraceEvent::CreateHardwareBreakpointHit(Params(), DeterminePc(), std::move(mRegisters));
    }
    case TraceeStopReason::Fork:
      return TraceEvent::CreateForkEvent_(Params(), mNewPid, std::move(mRegisters));
    case TraceeStopReason::VFork:
      TODO("Implement handling of TraceeStopReason::VFork");
    case TraceeStopReason::VForkDone:
      TODO("Implement handling of TraceeStopReason::VForkDone");
    case TraceeStopReason::Exec:
      return TraceEvent::CreateExecEvent(Params(), mExecPath, std::move(mRegisters));
    case TraceeStopReason::Clone:
      TODO("Implement handling of TraceeStopReason::Clone");
    case TraceeStopReason::Create: {
      const auto target =
        mConnection.GetSettings().mIsNonStop ? tc::ResumeTarget::Task : tc::ResumeTarget::AllNonRunningInProcess;
      return TraceEvent::CreateThreadCreated(Params(), {tc::RunType::Continue, target, 0}, std::move(mRegisters));
    }
    }
  }

  if (!init) {
    auto tc = Tracer::Get().GetController(mPid);
    auto t = tc != nullptr ? tc->GetTaskByTid(mTid) : nullptr;

    if (t && t->mBreakpointLocationStatus) {
      const auto locstat = t->ClearBreakpointLocStatus();
      return TraceEvent::CreateStepped(Params(), !locstat->mShouldResume, locstat, std::move(t->mNextResumeAction),
                                       std::move(mRegisters));
    }

    if (mSignal != SIGTRAP) {
      return TraceEvent::CreateSignal(Params(), std::move(mRegisters));
    }
  }

  // We got no stop reason. Defer to supervisor, let it figure it out.Nu
  return TraceEvent::CreateDeferToSupervisor(Params(), std::move(mRegisters), mControlKindIsAttached);
}

void
WaitEventParser::ParseFork(std::string_view data)
{
  ASSERT(mNewPid == 0, "new_pid already set");
  ASSERT(mNewTid == 0, "new_tid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  mNewPid = pid;
  mNewTid = tid;
}

void
WaitEventParser::ParseVFork(std::string_view data)
{
  ASSERT(mNewPid == 0, "new_pid already set");
  ASSERT(mNewTid == 0, "new_tid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  mNewPid = pid;
  mNewTid = tid;
}

void
WaitEventParser::SetVFork(Pid newpid, Tid newtid) noexcept
{
  ASSERT(mNewPid == 0, "new_pid already set");
  ASSERT(mNewTid == 0, "new_tid already set");
  mNewPid = newpid;
  mNewTid = newtid;
}

void
WaitEventParser::SetWatchpointAddress(AddrPtr addr) noexcept
{
  ASSERT(mWatchpointAddress == nullptr, "wp address already set");
  mWatchpointAddress = addr;
}

void
WaitEventParser::SetStopReason(TraceeStopReason stop) noexcept
{
  ASSERT(!mStopReason.has_value(), "Expected stop reason to not be set");
  mStopReason = stop;
}

void
WaitEventParser::SetPid(Pid process) noexcept
{
  ASSERT(mPid == 0, "pid already set");
  mPid = process;
}

void
WaitEventParser::SetTid(Tid thread) noexcept
{
  ASSERT(mTid == 0, "tid already set");
  mTid = thread;
}

void
WaitEventParser::SetExeced(std::string_view exec) noexcept
{
  mExecPath = DecodeHexString(exec);
}

void
WaitEventParser::ParseClone(std::string_view data) noexcept
{
  ASSERT(mNewPid == 0, "new_pid already set");
  ASSERT(mNewTid == 0, "new_pid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  mNewPid = pid;
  mNewTid = tid;
}

void
WaitEventParser::ParseEventTime(std::string_view data) noexcept
{
  ASSERT(mEventTime == 0, "Event time has already been seen?");
  int frameTime;
  auto value = std::from_chars(data.begin(), data.end(), frameTime, 16);
  if (value.ec == std::errc()) {
    mEventTime = frameTime;
  }
}

void
WaitEventParser::SetSyscallExit(int number) noexcept
{
  ASSERT(mSyscallNumber == 0, "syscall no already set");
  mSyscallNumber = number;
}

void
WaitEventParser::SetSyscallEntry(int number) noexcept
{
  ASSERT(mSyscallNumber == 0, "syscall no already set");
  mSyscallNumber = number;
}

std::vector<GdbThread>
WaitEventParser::ParseThreadsParameter(std::string_view input) noexcept
{
  ASSERT(mPid != 0, "process id not yet parsed");
  auto threads = ProtocolParseThreads(input);

  for (auto &t : threads) {
    if (t.pid == 0) {
      t.pid = mPid;
    }
  }
  return threads;
}

} // namespace mdb::gdb
/** LICENSE TEMPLATE */
#include "wait_event_parser.h"
#include "awaiter.h"
#include "bp.h"
#include "interface/remotegdb/connection.h"
#include "interface/remotegdb/shared.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "utils/debug_value.h"
#include <charconv>
#include <event_queue.h>
#include <supervisor.h>
#include <tracer.h>

namespace mdb::gdb {

WaitEventParser::WaitEventParser(RemoteConnection &conn) noexcept : connection(conn) {}

EventDataParam
WaitEventParser::param() const noexcept
{
  return EventDataParam{.target = pid, .tid = tid, .sig_or_code = signal};
}

static std::string
DecodeHexString(std::string_view hexString)
{
  std::string result{};
  result.reserve(hexString.size() / 2);
  const auto end = hexString.end();
  for (auto it = hexString.begin(); it != end; it += 2) {
    char character = 0;
    DebugValue res = std::from_chars(it, it + 2, character, 16);
    ASSERT(res.GetValue().ec == std::errc(), "Failed to convert hexstring char bytes to char");
    result.push_back(character);
  }
  return result;
}

void
WaitEventParser::parse_stop_reason(TraceeStopReason reason, std::string_view val) noexcept
{
  set_stop_reason(reason);
  switch (reason) {
  case TraceeStopReason::Watch:
  case TraceeStopReason::RWatch:
  case TraceeStopReason::AWatch: {
    const auto addr = ToAddress(val);
    ASSERT(addr, "Failed to parse address for remote stub watchpoint event from: '{}'", val);
    set_wp_address(addr.value());
    break;
  }
  case TraceeStopReason::SyscallEntry: {
    const auto sysnum = RemoteConnection::parse_hexdigits(val);
    set_syscall_entry(*sysnum);
    break;
  }
  case TraceeStopReason::SyscallReturn: {
    const auto sysnum = RemoteConnection::parse_hexdigits(val);
    set_syscall_exit(*sysnum);
    break;
  }
  case TraceeStopReason::Library:
  case TraceeStopReason::ReplayLog:
  case TraceeStopReason::SWBreak:
  case TraceeStopReason::HWBreak:
    break;
  case TraceeStopReason::Fork: {
    parse_fork(val);
  } break;
  case TraceeStopReason::VFork: {
    parse_vfork(val);
  } break;
  case TraceeStopReason::VForkDone: {
  } break;
  case TraceeStopReason::Exec:
    set_execed(val);
    break;
  case TraceeStopReason::Clone: {
    parse_clone(val);
  } break;
  case TraceeStopReason::Create:
    break;
  }
}

bool
WaitEventParser::is_stop_reason(u32 maybeStopReason) noexcept
{
  return std::find(StopReasonTokens.begin(), StopReasonTokens.end(), maybeStopReason) !=
         std::end(StopReasonTokens);
}

void
WaitEventParser::parse_pid_tid(std::string_view arg) noexcept
{
  const auto [pid, tid] = gdb::GdbThread::parse_thread(arg);
  set_pid(pid);
  set_tid(tid);
}

void
WaitEventParser::parse_core(std::string_view arg) noexcept
{
  ASSERT(core == 0, "core has already been set");
  u32 parsed_core{0};
  auto parse = std::from_chars(arg.data(), arg.data() + arg.size(), parsed_core, 16);
  if (parse.ec != std::errc()) {
    PANIC("Failed to parse core");
  }
  core = parsed_core;
}

// Determines PC value, from the payload sent by the remote. Returns nullopt if no PC was provided (or we
// couldn't parse it)
std::optional<std::uintptr_t>
WaitEventParser::determine_pc() const noexcept
{
  for (const auto &[no, reg] : registers) {
    if (no == arch.regs.rip_number) {
      u64 v;
      std::memcpy(&v, reg.data(), sizeof(v));
      return v;
    }
  }
  return {};
}

TraceEvent *
WaitEventParser::new_debugger_event(bool init) noexcept
{
  if (stop_reason) {
    switch (*stop_reason) {
    case TraceeStopReason::Watch:
      return TraceEvent::CreateWriteWatchpoint(param(), wp_address, std::move(registers));
    case TraceeStopReason::RWatch:
      return TraceEvent::CreateReadWatchpoint(param(), wp_address, std::move(registers));
    case TraceeStopReason::AWatch:
      return TraceEvent::CreateAccessWatchpoint(param(), wp_address, std::move(registers));
    case TraceeStopReason::SyscallEntry:
      return TraceEvent::CreateSyscallEntry(param(), syscall_no, std::move(registers));
    case TraceeStopReason::SyscallReturn:
      return TraceEvent::CreateSyscallExit(param(), syscall_no, std::move(registers));
    case TraceeStopReason::Library:
      return TraceEvent::CreateLibraryEvent(param(), std::move(registers));
    case TraceeStopReason::ReplayLog:
      TODO("Implement TraceeStopReason::ReplayLog");
    case TraceeStopReason::SWBreak: {
      return TraceEvent::CreateSoftwareBreakpointHit(param(), determine_pc(), std::move(registers));
    }
    case TraceeStopReason::HWBreak: {
      return TraceEvent::CreateHardwareBreakpointHit(param(), determine_pc(), std::move(registers));
    }
    case TraceeStopReason::Fork:
      return TraceEvent::CreateForkEvent_(param(), new_pid, std::move(registers));
    case TraceeStopReason::VFork:
      TODO("Implement handling of TraceeStopReason::VFork");
    case TraceeStopReason::VForkDone:
      TODO("Implement handling of TraceeStopReason::VForkDone");
    case TraceeStopReason::Exec:
      return TraceEvent::CreateExecEvent(param(), exec_path, std::move(registers));
    case TraceeStopReason::Clone:
      TODO("Implement handling of TraceeStopReason::Clone");
    case TraceeStopReason::Create: {
      const auto target =
        connection.settings().is_non_stop ? tc::ResumeTarget::Task : tc::ResumeTarget::AllNonRunningInProcess;
      return TraceEvent::CreateThreadCreated(param(), {tc::RunType::Continue, target}, std::move(registers));
    }
    }
  }

  if (!init) {
    auto tc = Tracer::Get().get_controller(pid);
    auto t = tc != nullptr ? tc->GetTaskByTid(tid) : nullptr;

    if (t && t->mBreakpointLocationStatus) {
      const auto locstat = t->ClearBreakpointLocStatus();
      return TraceEvent::CreateStepped(param(), !locstat->should_resume, locstat, std::move(t->mNextResumeAction),
                                       std::move(registers));
    }

    if (signal != SIGTRAP) {
      return TraceEvent::CreateSignal(param(), std::move(registers));
    }
  }

  // We got no stop reason. Defer to supervisor, let it figure it out.Nu
  return TraceEvent::CreateDeferToSupervisor(param(), std::move(registers), control_kind_is_attached);
}

void
WaitEventParser::parse_fork(std::string_view data)
{
  ASSERT(new_pid == 0, "new_pid already set");
  ASSERT(new_tid == 0, "new_tid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  new_pid = pid;
  new_tid = tid;
}

void
WaitEventParser::parse_vfork(std::string_view data)
{
  ASSERT(new_pid == 0, "new_pid already set");
  ASSERT(new_tid == 0, "new_tid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  new_pid = pid;
  new_tid = tid;
}

void
WaitEventParser::set_vfork(Pid newpid, Tid newtid) noexcept
{
  ASSERT(new_pid == 0, "new_pid already set");
  ASSERT(new_tid == 0, "new_tid already set");
  new_pid = newpid;
  new_tid = newtid;
}

void
WaitEventParser::set_wp_address(AddrPtr addr) noexcept
{
  ASSERT(wp_address == nullptr, "wp address already set");
  wp_address = addr;
}

void
WaitEventParser::set_stop_reason(TraceeStopReason stop) noexcept
{
  ASSERT(!stop_reason.has_value(), "Expected stop reason to not be set");
  stop_reason = stop;
}

void
WaitEventParser::set_pid(Pid process) noexcept
{
  ASSERT(pid == 0, "pid already set");
  pid = process;
}

void
WaitEventParser::set_tid(Tid thread) noexcept
{
  ASSERT(tid == 0, "tid already set");
  tid = thread;
}

void
WaitEventParser::set_execed(std::string_view exec) noexcept
{
  exec_path = DecodeHexString(exec);
}

void
WaitEventParser::parse_clone(std::string_view data) noexcept
{
  ASSERT(new_pid == 0, "new_pid already set");
  ASSERT(new_tid == 0, "new_pid already set");
  const auto [pid, tid] = gdb::GdbThread::parse_thread(data);
  new_pid = pid;
  new_tid = tid;
}

void
WaitEventParser::set_syscall_exit(int number) noexcept
{
  ASSERT(syscall_no == 0, "syscall no already set");
  syscall_no = number;
}

void
WaitEventParser::set_syscall_entry(int number) noexcept
{
  ASSERT(syscall_no == 0, "syscall no already set");
  syscall_no = number;
}

std::vector<GdbThread>
WaitEventParser::parse_threads_parameter(std::string_view input) noexcept
{
  ASSERT(pid != 0, "process id not yet parsed");
  auto threads = protocol_parse_threads(input);

  for (auto &t : threads) {
    if (t.pid == 0) {
      t.pid = pid;
    }
  }
  return threads;
}

} // namespace mdb::gdb
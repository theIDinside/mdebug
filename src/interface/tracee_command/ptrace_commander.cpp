/** LICENSE TEMPLATE */
#include "ptrace_commander.h"
#include "common.h"
#include "register_description.h"
#include "symbolication/objfile.h"
#include "utils/logger.h"
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <supervisor.h>
#include <sys/ptrace.h>
#include <unistd.h>

namespace mdb::tc {

PtraceCommander::PtraceCommander(Tid process_space_id) noexcept
    : TraceeCommandInterface(TargetFormat::Native, nullptr, TraceeInterfaceType::Ptrace), mProcFsMemFd(),
      mProcessId(process_space_id)
{
  const auto procfs_path = std::format("/proc/{}/mem", process_space_id);
  mProcFsMemFd = mdb::ScopedFd::Open(procfs_path, O_RDWR);
  ASSERT(mProcFsMemFd.IsOpen(), "failed to open memfd for {}", process_space_id);
}

bool
PtraceCommander::OnExec() noexcept
{
  auto tc = GetSupervisor();
  mProcessId = tc->TaskLeaderTid();
  DBGLOG(core, "Post Exec routine for {}", mProcessId);
  mProcFsMemFd = {};
  const auto procfs_path = std::format("/proc/{}/task/{}/mem", mProcessId, mProcessId);
  mProcFsMemFd = mdb::ScopedFd::Open(procfs_path, O_RDWR);
  ASSERT(mProcFsMemFd.IsOpen(), "Failed to open proc mem fs for {}", mProcessId);

  return mProcFsMemFd.IsOpen();
}

Interface
PtraceCommander::OnFork(SessionId pid) noexcept
{
  return std::make_unique<PtraceCommander>(pid);
}

bool
PtraceCommander::PostFork(TraceeController *parent) noexcept
{
  DBGLOG(core, "event was not vfork; disabling breakpoints in new address space.");
  // the new process space copies the old one; which contains breakpoints.
  // we restore the newly forked process space to the real contents. New breakpoints will be set
  // by the initialize -> configDone sequence
  for (auto &user : parent->GetUserBreakpoints().AllUserBreakpoints()) {
    if (auto loc = user->GetLocation(); loc) {
      DisableBreakpoint(mProcessId, *loc);
    }
  }
  return true;
}

Tid
PtraceCommander::TaskLeaderTid() const noexcept
{
  return mProcessId;
}

std::optional<Path>
PtraceCommander::ExecedFile() noexcept
{
  TODO("Implement PtraceCommander::execed_file() noexcept");
}

std::optional<std::vector<ObjectFileDescriptor>>
PtraceCommander::ReadLibraries() noexcept
{
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  auto rdebug_ext_res = ReadType(tracee_r_debug);
  if (rdebug_ext_res.is_error()) {
    DBGLOG(core, "Could not read rdebug_extended");
    return {};
  }
  r_debug_extended rdebug_ext = rdebug_ext_res.take_value();
  std::vector<ObjectFileDescriptor> objectFiles{};
  // TODO(simon): Make this asynchronous; so that instead of creating a symbol file inside the loop
  //  instead make a function that returns a promise of a symbol file. That promise gets added to a std::vector on
  //  each loop and then when the while loop has finished, we wait on all promises, collecting them.
  while (true) {
    // means we've hit some "entry" point in the linker-debugger interface; we need to wait for RT_CONSISTENT to
    // safely read "link map" containing the shared objects
    if (rdebug_ext.base.r_state != rdebug_ext.base.RT_CONSISTENT) {
      if (objectFiles.empty()) {
        DBGLOG(core, "Debug state not consistent: no information about obj files read");
        return {};
      } else {
        return objectFiles;
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
      auto namePointer = TPtr<char>{ map.l_name };
      const auto path = ReadNullTerminatedString(namePointer);
      if (!path) {
        DBGLOG(core, "Failed to read null-terminated string from tracee at {}", namePointer);
        return {};
      }
      objectFiles.emplace_back(path.value(), map.l_addr);
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

  return objectFiles;
}

ReadResult
PtraceCommander::ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  auto readBytes = pread64(mProcFsMemFd.Get(), read_buffer, size, address.GetRaw());
  if (readBytes > 0) {
    return ReadResult::Ok(static_cast<u32>(readBytes));
  } else if (readBytes == 0) {
    return ReadResult::EoF();
  } else {
    return ReadResult::SystemError(errno);
  }
}

TraceeWriteResult
PtraceCommander::WriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  const auto result = pwrite64(mProcFsMemFd.Get(), buf, size, addr.GetRaw());
  if (result > 0) {
    return TraceeWriteResult::Ok(static_cast<u32>(result));
  } else {
    return TraceeWriteResult::Error(errno);
  }
}

TaskExecuteResponse
PtraceCommander::ResumeTarget(TraceeController *tc, ResumeAction action, std::vector<Tid> *resumedThreads) noexcept
{
  for (auto &entry : tc->GetThreads()) {
    if (entry.mTask->CanContinue()) {
      if (resumedThreads) {
        resumedThreads->push_back(entry.mTid);
      }
      tc->ResumeTask(*entry.mTask, action);
    } else {
      DBGLOG(core, "[{}:resume:target] {} can_continue=false", tc->TaskLeaderTid(), entry.mTid);
    }
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::ResumeTask(TaskInfo &t, ResumeAction action) noexcept
{
  ASSERT(t.mUserVisibleStop || t.mTracerVisibleStop,
    "Was in neither user_stop ({}) or tracer_stop ({})",
    bool{ t.mUserVisibleStop },
    bool{ t.mTracerVisibleStop });
  if (t.mTracerVisibleStop) {
    action.mDeliverSignal = t.mLastWaitStatus.signal == SIGTRAP ? 0 : t.mLastWaitStatus.signal;
    if (t.bfRequestedStop) {
      action.mDeliverSignal = 0;
      t.ClearRequestedStopFlag();
    }

    DBGLOG(awaiter, "resuming {} with signal {}", t.mTid, action.mDeliverSignal);
    const auto ptrace_result = ptrace(action, t.mTid, nullptr, action.mDeliverSignal);
    if (ptrace_result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  } else {
    DBGLOG(awaiter,
      "[{}.{}:resume]: did not resume, not recorded signal delivery stop.",
      t.GetSupervisor()->TaskLeaderTid(),
      t.mTid);
  }
  t.SetCurrentResumeAction(action);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::StopTask(TaskInfo &t) noexcept
{
  const auto result = tgkill(mProcessId, t.mTid, SIGSTOP);
  if (result == -1) {
    DBGLOG(awaiter, "failed to send SIGSTOP to {}.{}", mProcessId, t.mTid);
    return TaskExecuteResponse::Error(errno);
  }
  DBGLOG(awaiter, "sent SIGSTOP to {}.{}", mProcessId, t.mTid);
  t.RequestedStop();
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  DBGLOG(core, "[{}.{}:bkpt]: enabling breakpoint at {}", TaskLeaderTid(), tid, location.Address());
  return InstallBreakpoint(tid, location.Address());
}

TaskExecuteResponse
PtraceCommander::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  DBGLOG(core, "[{}.{}:bkpt]: disabling breakpoint at {}", TaskLeaderTid(), tid, location.Address());
  const auto addr = location.Address().GetRaw();
  const auto read_value = ptrace(PTRACE_PEEKDATA, tid, addr, nullptr);
  if (read_value == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  const u8 original_byte = location.mOriginalByte;
  const u64 restore = ((read_value & ~0xff) | original_byte);

  if (auto res = ptrace(PTRACE_POKEDATA, tid, addr, restore); res == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::InstallBreakpoint(Tid tid, AddrPtr address) noexcept
{
  constexpr u64 bkpt = 0xcc;
  const auto addr = address.GetRaw();
  const auto read_value = ptrace(PTRACE_PEEKDATA, tid, addr, nullptr);

  const u64 installed_bp = ((read_value & ~0xff) | bkpt);
  if (const auto res = ptrace(PTRACE_POKEDATA, tid, addr, installed_bp); res == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  const u8 ins_byte = static_cast<u8>(read_value & 0xff);
  return TaskExecuteResponse::Ok(ins_byte);
}

TaskExecuteResponse
PtraceCommander::ReadRegisters(TaskInfo &t) noexcept
{
  if (const auto ptrace_result = ptrace(PTRACE_GETREGS, t.mTid, nullptr, t.NativeRegisters());
    ptrace_result == -1) {
    return TaskExecuteResponse::Error(errno);
  } else {
    return TaskExecuteResponse::Ok();
  }
}

TaskExecuteResponse
PtraceCommander::WriteRegisters(const user_regs_struct &) noexcept
{
  TODO("PtraceCommander::write_registers");
}

TaskExecuteResponse
PtraceCommander::SetProgramCounter(const TaskInfo &t, AddrPtr addr) noexcept
{
  constexpr auto ripOffset = offsetof(user_regs_struct, rip);
  const auto ptraceResult = ptrace(PTRACE_POKEUSER, t.mTid, ripOffset, addr.GetRaw());
  if (ptraceResult == -1) {
    return TaskExecuteResponse::Error(errno);
  }
  t.NativeRegisters()->rip = addr;
  return TaskExecuteResponse::Ok();
}

std::string_view
PtraceCommander::GetThreadName(Tid tid) noexcept
{
  if (mThreadNames.contains(tid)) {
    return mThreadNames[tid];
  }

  std::array<char, 256> pathbuf{};
  auto it = std::format_to(pathbuf.begin(), "/proc/{}/task/{}/comm", TaskLeaderTid(), tid);
  std::string_view path{ pathbuf.data(), it };
  auto file = mdb::ScopedFd::OpenFileReadOnly(path);
  char namebuf[16]{ 0 };
  auto len = ::read(file, namebuf, 16);

  if (len == -1) {
    const auto res = std::to_chars(namebuf, namebuf + 16, tid);
    if (res.ec != std::errc()) {
      return "???";
    }
    len = static_cast<u32>(res.ptr - namebuf);
  }
  std::string_view thrName{ namebuf, static_cast<std::string::size_type>(len) };
  if (thrName.back() == '\n') {
    thrName.remove_suffix(1);
  }
  auto newThreadName = std::format("{}: {}", tid, thrName);
  const auto &[iter, ok] = mThreadNames.emplace(tid, std::move(newThreadName));
  return iter->second;
}

TaskExecuteResponse
PtraceCommander::Disconnect(bool killTarget) noexcept
{
  using SupervisorState = TaskInfo::SupervisorState;
  if (killTarget && !GetSupervisor()->IsExited()) {
    for (auto &entry : GetSupervisor()->GetThreads()) {
      // Do we even care about this? It probably should be up to linux to handle it for us if there's an error
      // here.
      const auto _ = tgkill(mProcessId, entry.mTid, SIGKILL);
    }
    GetSupervisor()->ExitAll(SupervisorState::Killed);
  } else if (!GetSupervisor()->IsExited()) {
    mControl->StopAllTasks(nullptr);
    for (auto &user : mControl->GetUserBreakpoints().AllUserBreakpoints()) {
      mControl->GetUserBreakpoints().RemoveUserBreakpoint(user->mId);
    }
    for (auto &entry : GetSupervisor()->GetThreads()) {
      // Do we even care about this? It probably should be up to linux to handle it for us if there's an error
      // here.
      ptrace(PTRACE_DETACH, entry.mTid, nullptr, nullptr);
    }
    GetSupervisor()->ExitAll(SupervisorState::Detached);
  }
  PerformShutdown();
  return TaskExecuteResponse::Ok();
}

bool
PtraceCommander::PerformShutdown() noexcept
{
  return true;
}

std::shared_ptr<gdb::RemoteConnection>
PtraceCommander::RemoteConnection() noexcept
{
  return nullptr;
}

mdb::Expected<Auxv, Error>
PtraceCommander::ReadAuxiliaryVector() noexcept
{
  auto path = std::format("/proc/{}/auxv", TaskLeaderTid());
  DBGLOG(core, "Reading auxv for {} at {}", TaskLeaderTid(), path);
  mdb::ScopedFd procfile = mdb::ScopedFd::OpenFileReadOnly(path);
  // we can read 256 elements at a time (id + value = u64 * 2)
  static constexpr auto Count = 512;
  auto offset = 0;
  u64 buffer[Count];
  Auxv res;
  while (true) {
    const auto result = pread(procfile, buffer, sizeof(u64) * Count, offset);
    if (result == -1) {
      return Error{ .mSysErrorNumber = errno, .mErrorMessage = strerror(errno) };
    }
    ASSERT(result > (8 * 2),
      "Expected to read at least 1 element (last element should always be a 0, 0 pair, "
      "thus one element should always exist at the minimum) but read {}",
      result);
    const auto item_count = result / 8;

    res.mContents.reserve(res.mContents.size() + item_count);
    for (auto i = 0u; i < item_count; i += 2) {
      if (buffer[i] == 0 && buffer[i + 1] == 0) {
        return res;
      }
      res.mContents.emplace_back(buffer[i], buffer[i + 1]);
    }
    std::memset(buffer, 0, sizeof(u64) * Count);
    offset += sizeof(u64) * Count;
  }
}

} // namespace mdb::tc
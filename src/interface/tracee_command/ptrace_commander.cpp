#include "ptrace_commander.h"
#include "awaiter.h"
#include "common.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "register_description.h"
#include "symbolication/objfile.h"
#include "utils/logger.h"
#include "utils/scoped_fd.h"
#include <fcntl.h>
#include <supervisor.h>
#include <sys/ptrace.h>
#include <unistd.h>

namespace tc {

PtraceCommander::PtraceCommander(Tid process_space_id) noexcept
    : TraceeCommandInterface(TargetFormat::Native, nullptr, TraceeInterfaceType::Ptrace), procfs_memfd(),
      awaiter_thread(std::make_unique<AwaiterThread>(process_space_id)), process_id(process_space_id)
{
  const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
  procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
}

bool
PtraceCommander::OnExec() noexcept
{
  auto tc = GetSupervisor();
  process_id = tc->TaskLeaderTid();
  DBGLOG(core, "Post Exec routine for {}", process_id);
  procfs_memfd = {};
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", process_id, process_id);
  procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
  ASSERT(procfs_memfd.is_open(), "Failed to open proc mem fs for {}", process_id);

  return procfs_memfd.is_open();
}

Interface
PtraceCommander::OnFork(Pid pid) noexcept
{
  return std::make_unique<PtraceCommander>(pid);
}

Tid
PtraceCommander::TaskLeaderTid() const noexcept
{
  return process_id;
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
    auto linkmap = TPtr<link_map>{rdebug_ext.base.r_map};
    while (linkmap != nullptr) {
      auto map_res = ReadType(linkmap);
      if (!map_res.is_expected()) {
        DBGLOG(core, "Failed to read linkmap");
        return {};
      }
      auto map = map_res.take_value();
      auto name_ptr = TPtr<char>{map.l_name};
      const auto path = ReadNullTerminatedString(name_ptr);
      if (!path) {
        DBGLOG(core, "Failed to read null-terminated string from tracee at {}", name_ptr);
        return {};
      }
      obj_files.emplace_back(path.value(), map.l_addr);
      linkmap = TPtr<link_map>{map.l_next};
    }
    const auto next = TPtr<r_debug_extended>{rdebug_ext.r_next};
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

ReadResult
PtraceCommander::ReadBytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  auto read_bytes = pread64(procfs_memfd.get(), read_buffer, size, address.get());
  if (read_bytes > 0) {
    return ReadResult::Ok(static_cast<u32>(read_bytes));
  } else if (read_bytes == 0) {
    return ReadResult::EoF();
  } else {
    return ReadResult::SystemError(errno);
  }
}

TraceeWriteResult
PtraceCommander::WriteBytes(AddrPtr addr, u8 *buf, u32 size) noexcept
{
  const auto result = pwrite64(procfs_memfd.get(), buf, size, addr.get());
  if (result > 0) {
    return TraceeWriteResult::Ok(static_cast<u32>(result));
  } else {
    return TraceeWriteResult::Error(errno);
  }
}

TaskExecuteResponse
PtraceCommander::ResumeTarget(TraceeController *tc, RunType run) noexcept
{
  for (auto &t : tc->GetThreads()) {
    if (t->can_continue()) {
      tc->ResumeTask(*t, {run, tc::ResumeTarget::Task});
    }
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::ResumeTask(TaskInfo &t, RunType type) noexcept
{
  ASSERT(t.user_stopped || t.tracer_stopped, "Was in neither user_stop ({}) or tracer_stop ({})",
         bool{t.user_stopped}, bool{t.tracer_stopped});
  if (t.user_stopped || t.tracer_stopped) {
    const auto ptrace_result =
      ptrace(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, t.tid, nullptr, nullptr);
    if (ptrace_result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  }
  t.set_running(type);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::StopTask(TaskInfo &t) noexcept
{
  const auto result = tgkill(process_id, t.tid, SIGSTOP);
  if (result == -1) {
    return TaskExecuteResponse::Error(errno);
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::EnableBreakpoint(BreakpointLocation &location) noexcept
{
  return InstallBreakpoint(location.address());
}

TaskExecuteResponse
PtraceCommander::DisableBreakpoint(BreakpointLocation &location) noexcept
{
  DBGLOG(core, "[bkpt]: disabling breakpoint at {}", location.address());
  const auto addr = location.address().get();
  const auto read_value = ptrace(PTRACE_PEEKDATA, process_id, addr, nullptr);
  if (read_value == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  const u8 original_byte = location.original_byte;
  const u64 restore = ((read_value & ~0xff) | original_byte);

  if (auto res = ptrace(PTRACE_POKEDATA, process_id, addr, restore); res == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::InstallBreakpoint(AddrPtr address) noexcept
{
  constexpr u64 bkpt = 0xcc;
  const auto addr = address.get();
  const auto read_value = ptrace(PTRACE_PEEKDATA, process_id, addr, nullptr);

  const u64 installed_bp = ((read_value & ~0xff) | bkpt);
  if (const auto res = ptrace(PTRACE_POKEDATA, process_id, addr, installed_bp); res == -1) {
    return TaskExecuteResponse::Error(errno);
  }

  const u8 ins_byte = static_cast<u8>(read_value & 0xff);
  return TaskExecuteResponse::Ok(ins_byte);
}

TaskExecuteResponse
PtraceCommander::ReadRegisters(TaskInfo &t) noexcept
{
  if (const auto ptrace_result = ptrace(PTRACE_GETREGS, t.tid, nullptr, t.native_registers());
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
  constexpr auto rip_offset = offsetof(user_regs_struct, rip);
  const auto ptrace_result = ptrace(PTRACE_POKEUSER, t.tid, rip_offset, addr.get());
  if (ptrace_result == -1) {
    return TaskExecuteResponse::Error(errno);
  }
  t.native_registers()->rip = addr;
  return TaskExecuteResponse::Ok();
}

std::string_view
PtraceCommander::GetThreadName(Tid tid) noexcept
{

  std::array<char, 256> pathbuf{};
  auto it = fmt::format_to(pathbuf.begin(), "/proc/{}/task/{}/comm", TaskLeaderTid(), tid);
  std::string_view path{pathbuf.data(), it};
  auto file = utils::ScopedFd::open_read_only(path);
  char namebuf[16]{0};
  const auto len = ::read(file, namebuf, 16);

  if (len == -1) {
    return "???";
  }

  const auto &[nameit, ok] = thread_names.emplace(tid, std::string{namebuf, static_cast<u32>(len)});
  if (ok) {
    if (nameit->second.back() == '\n') {
      nameit->second.pop_back();
    }
    return nameit->second;
  } else {
    return "???";
  }
}

TaskExecuteResponse
PtraceCommander::Disconnect(bool kill_target) noexcept
{
  if (kill_target && !GetSupervisor()->IsExited()) {
    const auto result = tgkill(process_id, process_id, SIGKILL);
    if (result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  } else if(!GetSupervisor()->IsExited()) {
    const auto ptrace_result = ptrace(PTRACE_DETACH, process_id, nullptr, nullptr);
    if (ptrace_result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  }
  PerformShutdown();
  return TaskExecuteResponse::Ok();
}

bool
PtraceCommander::PerformShutdown() noexcept
{
  awaiter_thread->init_shutdown();
  return true;
}

bool
PtraceCommander::Initialize() noexcept
{
  awaiter_thread->start_awaiter_thread(this);
  return true;
}

std::shared_ptr<gdb::RemoteConnection>
PtraceCommander::RemoteConnection() noexcept
{
  return nullptr;
}

utils::Expected<Auxv, Error>
PtraceCommander::ReadAuxiliaryVector() noexcept
{
  auto path = fmt::format("/proc/{}/auxv", TaskLeaderTid());
  DBGLOG(core, "Reading auxv for {} at {}", TaskLeaderTid(), path);
  utils::ScopedFd procfile = utils::ScopedFd::open_read_only(path);
  // we can read 256 elements at a time (id + value = u64 * 2)
  static constexpr auto Count = 512;
  auto offset = 0;
  u64 buffer[Count];
  Auxv res;
  while (true) {
    const auto result = pread(procfile, buffer, sizeof(u64) * Count, offset);
    if (result == -1) {
      return Error{.sys_errno = errno, .err_msg = strerror(errno)};
    }
    ASSERT(result > (8 * 2),
           "Expected to read at least 1 element (last element should always be a 0, 0 pair, "
           "thus one element should always exist at the minimum) but read {}",
           result);
    const auto item_count = result / 8;

    res.vector.reserve(res.vector.size() + item_count);
    for (auto i = 0u; i < item_count; i += 2) {
      if (buffer[i] == 0 && buffer[i + 1] == 0) {
        return res;
      }
      res.vector.emplace_back(buffer[i], buffer[i + 1]);
    }
    std::memset(buffer, 0, sizeof(u64) * Count);
    offset += sizeof(u64) * Count;
  }
}

} // namespace tc
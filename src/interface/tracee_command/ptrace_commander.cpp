#include "ptrace_commander.h"
#include "awaiter.h"
#include "common.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "utils/scoped_fd.h"
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <supervisor.h>
#include <sys/ptrace.h>

namespace tc {

PtraceCommander::PtraceCommander(Tid process_space_id) noexcept
    : TraceeCommandInterface(), procfs_memfd(), awaiter_thread(std::make_unique<AwaiterThread>(process_space_id)),
      process_id(process_space_id)
{
  const auto procfs_path = fmt::format("/proc/{}/mem", process_space_id);
  procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
}

bool
PtraceCommander::reconfigure(TraceeController *tc) noexcept
{
  procfs_memfd = {};
  const auto procfs_path = fmt::format("/proc/{}/task/{}/mem", tc->task_leader, tc->task_leader);
  procfs_memfd = utils::ScopedFd::open(procfs_path, O_RDWR);
  process_id = tc->task_leader;
  return procfs_memfd.is_open();
}

Tid
PtraceCommander::task_leader() const noexcept
{
  return process_id;
}

TraceeReadResult
PtraceCommander::read_bytes(AddrPtr address, u32 size, u8 *read_buffer) noexcept
{
  auto read_bytes = pread64(procfs_memfd.get(), read_buffer, size, address.get());
  if (read_bytes > 0) {
    return TraceeReadResult::Ok(static_cast<u32>(read_bytes));
  } else if (read_bytes == 0) {
    return TraceeReadResult::EoF();
  } else {
    return TraceeReadResult::Error(errno);
  }
}

TraceeWriteResult
PtraceCommander::write_bytes(AddrPtr addr, u8 *buf, u32 size) noexcept
{
  const auto result = pwrite64(procfs_memfd.get(), buf, size, addr.get());
  if (result > 0) {
    return TraceeWriteResult::Ok(static_cast<u32>(result));
  } else {
    return TraceeWriteResult::Error(errno);
  }
}

TaskExecuteResponse
PtraceCommander::resume_task(TaskInfo &t, RunType type) noexcept
{
  (void)t;
  (void)type;
  ASSERT(t.user_stopped || t.tracer_stopped, "Was in neither user_stop ({}) or tracer_stop ({})",
         bool{t.user_stopped}, bool{t.tracer_stopped});
  if (t.user_stopped || t.tracer_stopped) {
    const auto ptrace_result =
        ptrace(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, t.tid, nullptr, nullptr);
    if (ptrace_result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  }
  t.stop_collected = false;
  t.user_stopped = false;
  t.tracer_stopped = false;
  t.set_dirty();
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::stop_task(TaskInfo &t) noexcept
{
  const auto result = tgkill(process_id, t.tid, SIGSTOP);
  if (result == -1) {
    return TaskExecuteResponse::Error(errno);
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::enable_breakpoint(BreakpointLocation &location) noexcept
{
  return install_breakpoint(location.address());
}

TaskExecuteResponse
PtraceCommander::disable_breakpoint(BreakpointLocation &location) noexcept
{
  DLOG("mdb", "[bkpt]: disabling breakpoint at {}", location.address());
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
PtraceCommander::install_breakpoint(AddrPtr address) noexcept
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
PtraceCommander::read_registers(TaskInfo &t) noexcept
{
  if (const auto ptrace_result = ptrace(PTRACE_GETREGS, t.tid, nullptr, t.registers); ptrace_result == -1) {
    return TaskExecuteResponse::Error(errno);
  } else {
    return TaskExecuteResponse::Ok();
  }
}

TaskExecuteResponse
PtraceCommander::write_registers(const user_regs_struct &) noexcept
{
  TODO("PtraceCommander::write_registers");
}

TaskExecuteResponse
PtraceCommander::set_pc(const TaskInfo &t, AddrPtr addr) noexcept
{
  constexpr auto rip_offset = offsetof(user_regs_struct, rip);
  const auto ptrace_result = ptrace(PTRACE_POKEUSER, t.tid, rip_offset, addr.get());
  if (ptrace_result == -1) {
    return TaskExecuteResponse::Error(errno);
  }
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
PtraceCommander::disconnect(bool terminate) noexcept
{
  if (terminate) {
    const auto result = tgkill(process_id, process_id, SIGKILL);
    if (result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  } else {
    const auto ptrace_result = ptrace(PTRACE_DETACH, process_id, nullptr, nullptr);
    if (ptrace_result == -1) {
      return TaskExecuteResponse::Error(errno);
    }
  }
  perform_shutdown();
  return TaskExecuteResponse::Ok();
}

bool
PtraceCommander::perform_shutdown() noexcept
{
  awaiter_thread->init_shutdown();
  return true;
}

bool
PtraceCommander::initialize() noexcept
{
  awaiter_thread->start_awaiter_thread(this);
  return true;
}

} // namespace tc
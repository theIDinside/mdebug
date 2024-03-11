#include "task.h"
#include "bp.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_frameunwinder.h"
#include <tracee/util.h>

TaskInfo::TaskInfo(pid_t tid, bool user_stopped) noexcept
    : tid(tid), wait_status(), user_stopped(user_stopped), tracer_stopped(true), initialized(false),
      cache_dirty(true), rip_dirty(true), exited(false), registers(new user_regs_struct{}),
      call_stack(new sym::CallStack{tid}), loc_stat()
{
}

TaskInfo
TaskInfo::create_stopped(pid_t tid)
{
  return TaskInfo{tid, true};
}

TaskInfo
TaskInfo::create_running(pid_t tid)
{
  return TaskInfo{tid, false};
}

AddrPtr
TaskInfo::pc() noexcept
{
  cache_registers();
  return registers->rip;
}

u64
TaskInfo::get_register(u64 reg_num) noexcept
{
  return ::get_register(registers, reg_num);
}

void
TaskInfo::cache_registers() noexcept
{
  if (cache_dirty) {
    PTRACE_OR_PANIC(PTRACE_GETREGS, tid, nullptr, registers);
    cache_dirty = false;
    rip_dirty = false;
  }
}

static void
decode_eh_insts(sym::UnwindInfoSymbolFilePair info, sym::CFAStateMachine &state) noexcept
{
  // TODO(simon): Refactor DwarfBinaryReader, splitting it into 2 components, a BinaryReader and a
  // DwarfBinaryReader which inherits from that. in this instance, a BinaryReader suffices, we don't need to
  // actually know how to read DWARF binary data here.
  DwarfBinaryReader reader{nullptr, info.info->cie->instructions.data(), info.info->cie->instructions.size()};

  sym::decode(reader, state, info.info);
  DwarfBinaryReader fde{nullptr, info.info->fde_insts.data(), info.info->fde_insts.size()};
  sym::decode(fde, state, info.info);
}

const std::vector<AddrPtr> &
TaskInfo::return_addresses(TraceeController *tc, CallStackRequest req) noexcept
{
  static constexpr auto X86_64_RIP_REGISTER = 16;
  if (!call_stack->dirty)
    return call_stack->pcs;
  else {
    call_stack->pcs.clear();
  }

  if (cache_dirty)
    cache_registers();

  // initialize bottom frame's registers with actual live register contents
  auto &buf = call_stack->reg_unwind_buffer;
  buf.clear();
  buf.reserve(call_stack->pcs.capacity());
  buf.push_back({});
  {
    auto &init = buf.back();
    for (auto i = 0; i <= 16; ++i) {
      init[i] = get_register(i);
    }
  }

  sym::UnwindIterator it{tc, registers->rip};
  ASSERT(!it.is_null(), "Could not find unwinder for pc {}", AddrPtr{registers->rip});
  auto uninfo = it.get_info(registers->rip);
  ASSERT(uninfo.has_value(), "unwind info iterator returned null for 0x{:x}", registers->rip);
  sym::CFAStateMachine cfa_state = sym::CFAStateMachine::Init(*tc, *this, uninfo.value(), registers->rip);

  const auto get_current_pc = [&fr = buf]() noexcept { return fr.back()[X86_64_RIP_REGISTER]; };
  switch (req.req) {
  case CallStackRequest::Type::Full: {
    for (auto uinf = uninfo; uinf.has_value(); uinf = it.get_info(get_current_pc())) {
      const auto pc = get_current_pc();
      cfa_state.reset(uinf.value(), buf.back(), pc);
      call_stack->pcs.push_back(pc);
      decode_eh_insts(uinf.value(), cfa_state);
      buf.push_back(cfa_state.resolve_frame_regs(buf.back()));
    }
    call_stack->dirty = false;
    break;
  }
  case CallStackRequest::Type::Partial: {
    for (auto uinf = uninfo; uinf.has_value() && req.count != 0; uinf = it.get_info(get_current_pc())) {
      const auto pc = get_current_pc();
      cfa_state.reset(uinf.value(), buf.back(), pc);
      call_stack->pcs.push_back(pc);
      decode_eh_insts(uinf.value(), cfa_state);
      buf.push_back(cfa_state.resolve_frame_regs(buf.back()));
      --req.count;
    }
    break;
  }
  }
  return call_stack->pcs;
}

void
TaskInfo::set_taskwait(TaskWaitResult wait) noexcept
{
  wait_status = wait.ws;
}

void
TaskInfo::consume_wait() noexcept
{
  int stat;
  waitpid(tid, &stat, 0);
  tracer_stopped = true;
  user_stopped = true;
}

void
TaskInfo::ptrace_resume(RunType type) noexcept
{
  ASSERT(user_stopped || tracer_stopped, "Was in neither user_stop ({}) or tracer_stop ({})", bool{user_stopped},
         bool{tracer_stopped});
  if (user_stopped) {
    DLOG("mdb", "[ptrace]: restarting {} ({}) from user-stop", tid,
         type == RunType::Continue ? "PTRACE_CONT" : "PTRACE_SINGLESTEP");
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  } else if (tracer_stopped) {
    DLOG("mdb", "[ptrace]: restarting {} ({}) from tracer-stop", tid,
         type == RunType::Continue ? "PTRACE_CONT" : "PTRACE_SINGLESTEP");
    PTRACE_OR_PANIC(type == RunType::Continue ? PTRACE_CONT : PTRACE_SINGLESTEP, tid, nullptr, nullptr);
  }
  stop_collected = false;
  user_stopped = false;
  tracer_stopped = false;
  set_dirty();
}

WaitStatus
TaskInfo::pending_wait_status() const noexcept
{
  ASSERT(wait_status.ws != WaitStatusKind::NotKnown, "Wait status unknown for {}", tid);
  return wait_status;
}

void
TaskInfo::step_over_breakpoint(TraceeController *tc, RunType resume_action) noexcept
{
  ASSERT(loc_stat.has_value(), "Requires a valid bpstat");
  auto loc = tc->pbps.location_at(loc_stat->loc);
  auto user_ids = loc->loc_users();
  DLOG("mdb", "[TaskInfo {}] Stepping over bps {} at {}", tid, fmt::join(user_ids, ", "), loc->address());

  loc->disable(tc->task_leader);
  loc_stat->stepped_over = true;
  loc_stat->re_enable_bp = true;
  loc_stat->should_resume = resume_action != RunType::None;
  ptrace_resume(RunType::Step);
}

void
TaskInfo::set_stop() noexcept
{
  user_stopped = true;
  tracer_stopped = true;
}

void
TaskInfo::initialize() noexcept
{
  initialized = true;
}

bool
TaskInfo::can_continue() noexcept
{
  return initialized && (user_stopped || tracer_stopped) && !exited;
}

void
TaskInfo::set_dirty() noexcept
{
  cache_dirty = true;
  rip_dirty = true;
  call_stack->dirty = true;
}

void
TaskInfo::add_bpstat(AddrPtr address) noexcept
{
  loc_stat = LocationStatus{.loc = address, .should_resume = false, .stepped_over = false, .re_enable_bp = false};
}

void
TaskInfo::remove_bpstat() noexcept
{
  loc_stat = std::nullopt;
}

void
TaskStepInfo::step_taken_to(AddrPtr rip) noexcept
{
  this->rip = rip;
  --steps;
}

bool
TaskInfo::is_stopped() const noexcept
{
  return user_stopped;
}

bool
TaskInfo::stop_processed() const noexcept
{
  return stop_collected;
}

TaskVMInfo
TaskVMInfo::from_clone_args(const clone_args &cl_args) noexcept
{
  return {.stack_low = cl_args.stack, .stack_size = cl_args.stack_size, .tls = cl_args.tls};
}

/*static*/ CallStackRequest
CallStackRequest::partial(u8 count) noexcept
{
  return CallStackRequest{.req = Type::Partial, .count = count};
}

/*static*/ CallStackRequest
CallStackRequest::full() noexcept
{
  return CallStackRequest{.req = Type::Full, .count = 0};
}
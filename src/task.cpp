#include "task.h"
#include "breakpoint.h"
#include "common.h"
#include "ptrace.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_frameunwinder.h"
#include <sys/ptrace.h>
#include <sys/user.h>

TaskInfo::TaskInfo(pid_t tid, bool user_stopped) noexcept
    : tid(tid), wait_status(), user_stopped(user_stopped), tracer_stopped(true), initialized(false),
      cache_dirty(true), rip_dirty(true), exited(false), registers(new user_regs_struct{}),
      call_stack(new sym::CallStack{tid})
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
decode_eh_insts(const sym::UnwindInfo *inf, sym::CFAStateMachine &state) noexcept
{
  DwarfBinaryReader reader{inf->cie->instructions.data(), inf->cie->instructions.size()};

  const auto cie_cnt = sym::decode(reader, state, inf);
  DLOG("eh", "CIE ins decoded={}", cie_cnt);
  DwarfBinaryReader fde{inf->fde_insts.data(), inf->fde_insts.size()};
  const auto fde_cnt = sym::decode(fde, state, inf);
  DLOG("eh", "FDE ins decoded={}", fde_cnt);
}

const std::vector<AddrPtr> &
TaskInfo::return_addresses(TraceeController *tc, CallStackRequest req) noexcept
{
  if (!call_stack->dirty)
    return call_stack->pcs;
  else {
    call_stack->pcs.clear();
  }

  if (cache_dirty)
    cache_registers();

  // initialize bottom frame's registers with actual live register contents
  DLOG("mdb", "servicing return addresses...");
  auto &buf = call_stack->reg_unwind_buffer;
  buf.clear();
  buf.reserve(call_stack->pcs.size());
  buf.push_back({});
  call_stack->resolved = req.count;
  {
    auto &init = buf.back();
    for (auto i = 0; i <= 16; ++i) {
      init[i] = get_register(i);
    }
  }

  sym::UnwindIterator it{tc, registers->rip};
  DLOG("mdb", "Unwind iterator is null: {} for pc: {}", it.is_null(), registers->rip);
  ASSERT(!it.is_null(), "Could not find unwinder for pc {}", AddrPtr{registers->rip});
  const sym::UnwindInfo *un_info = it.get_info(registers->rip);
  ASSERT(un_info != nullptr, "unwind info iterator returned null for 0x{:x}", registers->rip);
  sym::CFAStateMachine cfa_state = sym::CFAStateMachine::Init(tc, this, un_info, registers->rip);

  const auto get_current_pc = [&fr = buf]() noexcept { return fr.back()[X86_64_RIP_REGISTER]; };
  DLOG("mdb", "servicing return addresses...");
  switch (req.req) {
  case CallStackRequest::Type::Full: {
    for (auto uinf = un_info; uinf != nullptr; uinf = it.get_info(get_current_pc())) {
      const auto pc = get_current_pc();
      cfa_state.reset(uinf, buf.back(), pc);
      call_stack->pcs.push_back(pc);
      DLOG("eh", "[unwind] CIE=0x{:x}, FDE=0x{:x}, pc=0x{:x}", uinf->cie->offset, uinf->fde_eh_offset, pc);
      decode_eh_insts(uinf, cfa_state);
      buf.push_back(cfa_state.resolve_frame_regs(buf.back()));
    }
    call_stack->dirty = false;
  }
  case CallStackRequest::Type::Partial: {
    for (auto uinf = un_info; uinf != nullptr && req.count != 0; uinf = it.get_info(get_current_pc())) {
      const auto pc = get_current_pc();
      cfa_state.reset(uinf, buf.back(), pc);
      call_stack->pcs.push_back(pc);
      DLOG("eh", "[unwind] CIE=0x{:x}, FDE=0x{:x}, pc=0x{:x}", uinf->cie->offset, uinf->fde_eh_offset, pc);
      decode_eh_insts(uinf, cfa_state);
      buf.push_back(cfa_state.resolve_frame_regs(buf.back()));
      --req.count;
    }
    call_stack->resolved = call_stack->resolved - req.count;
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
  ASSERT(bstat.has_value(), "Requires a valid bpstat");
  auto bp = tc->bps.get_by_id(bstat->bp_id);
  DLOG("mdb", "[TaskInfo {}] Stepping over bp {} at {}", tid, bstat->bp_id, bp->address);

  bp->disable(tc->task_leader);
  bstat->stepped_over = true;
  bstat->re_enable_bp = true;
  bstat->should_resume = resume_action != RunType::None;
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
TaskInfo::add_bpstat(Breakpoint *bp) noexcept
{
  bstat = BpStat{.bp_id = bp->id, .type = bp->type(), .stepped_over = false, .re_enable_bp = false};
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
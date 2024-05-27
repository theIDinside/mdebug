#include "task.h"
#include "arch.h"
#include "bp.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "supervisor.h"
#include "symbolication/callstack.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "utils/util.h"
#include <sys/user.h>
#include <tracee/util.h>
#include <utility>

TaskInfo::TaskInfo(pid_t tid, bool user_stopped, TargetFormat format, ArchType arch) noexcept
    : tid(tid), wait_status(), user_stopped(user_stopped), tracer_stopped(true), initialized(false),
      cache_dirty(true), rip_dirty(true), exited(false), call_stack(new sym::CallStack{tid}), loc_stat()
{
  regs = {.arch = arch, .data_format = format, .rip_dirty = true, .cache_dirty = true, .registers = nullptr};

  switch (format) {
  case TargetFormat::Native:
    regs.registers = new user_regs_struct{};
    break;
  case TargetFormat::Remote:
    switch (arch) {
    case ArchType::X86_64:
      regs.x86_block = new RegisterBlock<ArchType::X86_64>{};
      break;
    case ArchType::COUNT:
      std::unreachable();
      break;
    }
    break;
  }
}

TaskInfo
TaskInfo::create_running(pid_t tid, TargetFormat format, ArchType arch)
{
  return TaskInfo{tid, false, format, arch};
}

user_regs_struct *
TaskInfo::native_registers() const noexcept
{
  ASSERT(regs.data_format == TargetFormat::Native, "Used in the wrong context");
  return regs.registers;
}

RegisterBlock<ArchType::X86_64> *
TaskInfo::remote_x86_registers() const noexcept
{
  ASSERT(regs.data_format == TargetFormat::Remote, "Used in the wrong context");
  return regs.x86_block;
}

void
TaskInfo::remote_from_hexdigit_encoding(std::string_view hex_encoded) noexcept
{
  ASSERT(regs.data_format == TargetFormat::Remote, "Expected remote format");
  regs.x86_block->from_hexdigit_encoding(hex_encoded);
  set_updated();
}

u64
TaskInfo::get_register(u64 reg_num) noexcept
{
  switch (regs.data_format) {
  case TargetFormat::Native:
    return ::get_register(regs.registers, reg_num);
  case TargetFormat::Remote:
    static_assert(utils::castenum(ArchType::COUNT) == 1, "Supported architectures have increased");
    return regs.x86_block->get_64bit_reg(reg_num);
    break;
  }
}

u64
TaskInfo::unwind_buffer_register(u8 level, u16 register_number) const noexcept
{
  return call_stack->unwind_buffer_register(level, register_number);
}

void
TaskInfo::set_registers(const std::vector<std::pair<u32, std::vector<u8>>> &data) noexcept
{
  regs.x86_block->set_registers(data);
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

  if (cache_dirty) {
    tc->cache_registers(*this);
  }

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

  auto pc = get_pc();

  sym::UnwindIterator it{tc, pc};
  ASSERT(!it.is_null(), "Could not find unwinder for pc {}", AddrPtr{pc});
  auto uninfo = it.get_info(pc);
  ASSERT(uninfo.has_value(), "unwind info iterator returned null for 0x{:x}", pc);
  sym::CFAStateMachine cfa_state = sym::CFAStateMachine::Init(*tc, *this, uninfo.value(), pc);

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

WaitStatus
TaskInfo::pending_wait_status() const noexcept
{
  ASSERT(wait_status.ws != WaitStatusKind::NotKnown, "Wait status unknown for {}", tid);
  return wait_status;
}

std::uintptr_t
TaskInfo::get_rbp() const noexcept
{
  switch (regs.data_format) {
  case TargetFormat::Native:
    return regs.registers->rbp;
  case TargetFormat::Remote:
    static_assert(utils::castenum(ArchType::COUNT) == 1, "new architecture types have been added");
    return regs.x86_block->get_rbp();
  }
}

std::uintptr_t
TaskInfo::get_pc() const noexcept
{
  switch (regs.data_format) {
  case TargetFormat::Native:
    return regs.registers->rip;
  case TargetFormat::Remote:
    static_assert(utils::castenum(ArchType::COUNT) == 1, "new architecture types have been added");
    return regs.x86_block->get_pc();
  }
}

std::uintptr_t
TaskInfo::get_rsp() const noexcept
{
  switch (regs.data_format) {
  case TargetFormat::Native:
    return regs.registers->rsp;
  case TargetFormat::Remote:
    static_assert(utils::castenum(ArchType::COUNT) == 1, "new architecture types have been added");
    return regs.x86_block->get_rsp();
  }
}

std::uintptr_t
TaskInfo::get_orig_rax() const noexcept
{
  switch (regs.data_format) {
  case TargetFormat::Native:
    return regs.registers->orig_rax;
  case TargetFormat::Remote:
    return regs.x86_block->get_64bit_reg(57);
  }
}

void
TaskInfo::step_over_breakpoint(TraceeController *tc, tc::ResumeAction resume_action) noexcept
{
  ASSERT(loc_stat.has_value(), "Requires a valid bpstat");
  auto loc = tc->pbps.location_at(loc_stat->loc);
  auto user_ids = loc->loc_users();
  DBGLOG(core, "[TaskInfo {}] Stepping over bps {} at {}", tid, fmt::join(user_ids, ", "), loc->address());

  auto &control = tc->get_interface();
  loc->disable(control);
  loc_stat->stepped_over = true;
  loc_stat->re_enable_bp = true;
  loc_stat->should_resume = resume_action.type != tc::RunType::None;

  next_resume_action = resume_action;

  const auto result = control.resume_task(*this, tc::RunType::Step);
  ASSERT(result.is_ok(), "Failed to step over breakpoint");
}

void
TaskInfo::set_stop() noexcept
{
  user_stopped = true;
  tracer_stopped = true;
}

void
TaskInfo::set_running(tc::RunType type) noexcept
{
  stop_collected = false;
  user_stopped = false;
  tracer_stopped = false;
  last_resume_command = type;
  set_dirty();
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
TaskInfo::set_updated() noexcept
{
  rip_dirty = false;
  cache_dirty = false;
}

void
TaskInfo::add_bpstat(AddrPtr address) noexcept
{
  loc_stat = LocationStatus{.loc = address, .should_resume = false, .stepped_over = false, .re_enable_bp = false};
}

std::optional<LocationStatus>
TaskInfo::clear_bpstat() noexcept
{
  const auto copy = loc_stat;
  loc_stat = std::nullopt;
  return copy;
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

void
TaskInfo::collect_stop() noexcept
{
  stop_collected = true;
  tracer_stopped = true;
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
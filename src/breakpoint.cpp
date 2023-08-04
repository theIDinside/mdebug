#include "breakpoint.h"
#include "tracee_controller.h"
#include <sys/ptrace.h>
#include <utility>

Breakpoint::Breakpoint(AddrPtr addr, u8 original_byte, u32 id, BpType type) noexcept
    : original_byte(original_byte), bp_type(type), id(id), times_hit(0), address(addr), enabled(true)
{
}

void
Breakpoint::enable(Tid tid) noexcept
{
  if (!enabled) {
    constexpr u64 bkpt = 0xcc;
    const auto read_value = ptrace(PTRACE_PEEKDATA, tid, address.get(), nullptr);
    const u64 installed_bp = ((read_value & ~0xff) | bkpt);
    ptrace(PTRACE_POKEDATA, tid, address.get(), installed_bp);
    enabled = true;
  }
}

void
Breakpoint::disable(Tid tid) noexcept
{
  if (enabled) {
    const auto read_value = ptrace(PTRACE_PEEKDATA, tid, address.get(), nullptr);
    const u64 restore = ((read_value & ~0xff) | original_byte);
    ptrace(PTRACE_POKEDATA, tid, address.get(), restore);
    enabled = false;
  }
}

BpType
Breakpoint::type() const noexcept
{
  return bp_type;
}

#define UL(BpEvt) std::to_underlying(BpEventType::BpEvt)

BpEventType
Breakpoint::event_type() const noexcept
{
  const auto t = bp_type.type;
  DLOG("mdb", "Breakpoint type: {:b}", bp_type.type);
  if (bp_type.type & 0b1111) {
    const auto underlying = (UL(Both) * (t > 0b1111) + (UL(UserBreakpointHit) * t <= 0b1111));
    return (BpEventType)underlying;
  } else {
    return BpEventType::TracerBreakpointHit;
  }
}

std::vector<BpStat>::iterator
BreakpointMap::find_bpstat(Tid tid) noexcept
{
  return ::find(bpstats, [tid = tid](auto &bpstat) { return bpstat.tid == tid; });
}
bool
BreakpointMap::has_value(std::vector<BpStat>::iterator it) noexcept
{
  return it != std::end(bpstats);
}

void
BreakpointMap::add_bpstat_for(TaskInfo *t, Breakpoint *bp)
{
  DLOG("mdb", "Adding bpstat for {} on breakpoint {}", t->tid, bp->id);
  bpstats.push_back({.tid = t->tid, .bp_id = bp->id, .type = bp->type(), .stepped_over = false});
  bp->times_hit++;
  t->user_stopped = true;
  t->tracer_stopped = true;
}

bool
BreakpointMap::insert(AddrPtr addr, u8 ins_byte, BpType type) noexcept
{
  if (contains(addr))
    return false;
  breakpoints.push_back(Breakpoint{addr, ins_byte, bp_id_counter++, type});
  return true;
}

void
BreakpointMap::clear(TraceeController *target, BpType type) noexcept
{
  std::erase_if(breakpoints, [t = this, target, type](Breakpoint &bp) {
    if (bp.type() & type) {
      // if enabled, and if new setting, means that it's not a combination of any breakpoint types left, disable it
      // and erase it.
      if (bp.bp_type.source && type.source) {
        t->source_breakpoints.erase(bp.id);
      }
      if (bp.bp_type.function && type.function) {
        t->fn_breakpoint_names.erase(bp.id);
      }

      // If flipping off all `type` bits in bp results in == 0, means it should be deleted.
      if (bp.enabled && !(bp.type() & type)) {
        bp.disable(target->task_leader);
        return true;
      } else {
        // turn off all types passed in as `type`, keep the rest
        bp.bp_type.unset(type);
      }
    }
    return false;
  });
}

void
BreakpointMap::clear_breakpoint_stats() noexcept
{
  bpstats.clear();
}

void
BreakpointMap::disable_breakpoint(u16 id) noexcept
{
  auto bp = get_by_id(id);
  bp->disable(address_space_tid);
}

void
BreakpointMap::enable_breakpoint(u16 id) noexcept
{
  auto bp = get_by_id(id);
  bp->enable(address_space_tid);
}

Breakpoint *
BreakpointMap::get_by_id(u32 id) noexcept
{
  auto it = std::find_if(breakpoints.begin(), breakpoints.end(), [&](const auto &bp) { return bp.id == id; });
  ASSERT(it != end(breakpoints), "Expected to find a breakpoint with id {}", id);
  return &(*it);
}

Breakpoint *
BreakpointMap::get(AddrPtr addr) noexcept
{
  auto iter = find(breakpoints, [addr](auto &bp) { return bp.address == addr; });
  if (iter != std::cend(breakpoints))
    return &(*iter);
  else
    return nullptr;
}

void
BreakpointMap::remove_breakpoint(AddrPtr addr, BpType type) noexcept
{
  DLOG("mdb", "Remove breakpoint type {} @ {}", type, addr);
  std::erase_if(breakpoints, [pid = address_space_tid, addr, type](Breakpoint &bp) {
    if (bp.address == addr) {
      bp.bp_type.unset(type);
      if (bp.bp_type.type == 0) {
        bp.disable(pid);
        DLOG("mdb", "Deleted breakpoint at {}", bp.address);
        return true;
      }
    }
    return false;
  });
}

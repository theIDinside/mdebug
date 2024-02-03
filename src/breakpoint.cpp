#include "breakpoint.h"
#include "events/event.h"
#include "ptrace.h"
#include "supervisor.h"

extern bool MDB_LOG;

Breakpoint::Breakpoint(AddrPtr addr, u8 original_byte, u32 id, BpType type) noexcept
    : original_byte(original_byte), bp_type(type), id(id), address(addr)
{
  DLOG("mdb", "[bkpt]: bp {} created for {} = {}", id, addr, type);
}

Breakpoint::Breakpoint(Breakpoint &&b) noexcept
    : original_byte(b.original_byte), bp_type(b.type()), id(b.id), address(b.address), enabled(b.enabled),
      times_hit(b.times_hit), on_notify(b.on_notify), stop_these(std::move(b.stop_these)),
      temporary_notes(std::move(b.temporary_notes))
{
}

Breakpoint &
Breakpoint::operator=(Breakpoint &&b) noexcept
{
  if (this == &b)
    return *this;
  original_byte = b.original_byte;
  bp_type = b.bp_type;
  id = b.id;
  address = b.address;
  enabled = b.enabled;
  times_hit = b.times_hit;
  on_notify = b.on_notify;
  stop_these = std::move(b.stop_these);
  temporary_notes = std::move(b.temporary_notes);
  return *this;
}

void
Breakpoint::enable(Tid tid) noexcept
{
  if (!enabled) {
    DLOG("mdb", "[bkpt]: enabling {} (tid: {})", id, tid);
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
    DLOG("mdb", "[bkpt]: disabling {} (tid: {})", id, tid);
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

OnBpHit
Breakpoint::on_hit(TraceeController &tc, TaskInfo &t) noexcept
{
  ++times_hit;
  switch (event_type()) {
  // even if underlying bp is both user and tracer bp; it always handles it prioritized as user.
  case BpEventType::Both: {
    if (bp_type.shared_object_load) {
      tc.on_so_event();
    }
    [[fallthrough]];
  }
  case BpEventType::UserBreakpointHit: {
    // TODO(simon): if breakpoint doesn't stop all, emit stop event directly, but only for that one thread.
    //   N.B! For that to be solved we have multiple problems to consider
    //   if we don't stop all, any action then taken by any part of the debugger, will have to keep in mind
    //   that all threads aren't (might not be) stopped. So, if for instance some code wants to set a breakpoint
    //   somewhere in the tracee, first, that part of the code will have to stop all threads, reap the wait status
    //   and _then_ proceed with it's actions of what it wants to do, which is setting a breakpoint. After it's
    //   done, it has to restart/reset the state of the program, to what it was before it stopped everything. This
    //   complexity absolutely astronomically balloons everything. Therefore, for now at least, it's decided that
    //   _any_ user breakpoint that gets hit, will stop all threads. The user can still resume/continue, step, do
    //   "next line" etc, on individual threads, but as soon as a bp is hit, all threads will stop.
    //   the reason for this complexity, is because if MDB wants to set a breakpoint it has to write to tracee
    //   memory, and for that to work reliably it must be stopped.
    if (!ignore_task(t)) {
      tc.stop_all(&t);
      switch (stop_notification(t)) {
      case BpNote::BreakpointHit: {
        tc.all_stopped_observer.add_notification<BreakpointHit>(tc, id, t.tid);
        return OnBpHit::Stop;
      }
      case BpNote::FinishedFunction:
        tc.all_stopped_observer.add_notification<Step>(tc, t.tid, "Finished function");
        return OnBpHit::Stop;
      }
    }
    break;
  }
  case BpEventType::TracerBreakpointHit: {
    if (bp_type.shared_object_load) {
      tc.on_so_event();
    }
  } break;
  }
  return OnBpHit::Continue;
}

bool
Breakpoint::ignore_task(const TaskInfo &t) noexcept
{
  return stop_these && !stop_these->contains(t.tid);
}

BpNote
Breakpoint::stop_notification(const TaskInfo &task) noexcept
{
  if (temporary_notes) {
    auto i = temporary_notes->find(task.tid);
    if (i != std::end(*temporary_notes)) {
      const auto n = i->second;
      temporary_notes->erase(i);
      if (temporary_notes->empty())
        temporary_notes.reset();
      return n;
    }
  }
  return on_notify;
}

void
Breakpoint::set_note(BpNote bpnote) noexcept
{
  on_notify = bpnote;
}

void
Breakpoint::set_temporary_note(const TaskInfo &t, BpNote n) noexcept
{
  if (!temporary_notes) {
    temporary_notes = std::make_unique<TemporaryNotes>();
  }
  temporary_notes->insert({t.tid, n});
}

void
Breakpoint::add_stop_for(Tid tid) noexcept
{
  if (!stop_these) {
    stop_these = std::make_unique<StopSet>();
  }
  stop_these->insert(tid);
}

#define UL(BpEvt) std::to_underlying(BpEventType::BpEvt)

BpEventType
Breakpoint::event_type() const noexcept
{
  const auto t = bp_type.type;
  if (bp_type.type & 0b1111) {
    const auto underlying = (UL(Both) * (t > 0b1111) + (UL(UserBreakpointHit) * t <= 0b1111));
    return (BpEventType)underlying;
  } else {
    return BpEventType::TracerBreakpointHit;
  }
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
  DLOG("mdb", "[bkpt]: remove {} at {}", type, addr);
  std::erase_if(breakpoints, [pid = address_space_tid, addr, type](Breakpoint &bp) {
    if (bp.address == addr) {
      bp.bp_type.unset(type);
      if (bp.bp_type.type == 0) {
        bp.disable(pid);
        DLOG("mdb", "[bkpt] deleted bp {} at {}", bp.id, bp.address);
        return true;
      }
    }
    return false;
  });
}

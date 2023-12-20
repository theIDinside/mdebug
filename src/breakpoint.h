#pragma once
#include "common.h"
#include <unordered_set>

struct TraceeController;
struct TaskInfo;

enum class BreakpointType : std::uint8_t
{
  // User breakpoints
  Source = 1 << 0,
  Function = 1 << 1,
  Address = 1 << 2,
  // Tracer breakpoints & User breakpoints
  ResumeAddress = 1 << 3,
  SharedObjectEvent = 1 << 4,
  Exception = 1 << 5,
  LongJump = 1 << 6
};

struct BpType
{
  union
  {
    u8 type = 0;
    struct
    {
      bool lsb_padding : 1; // low bit
      bool source : 1;
      bool function : 1;
      bool address : 1;
      bool resume_address : 1;
      bool shared_object_load : 1;
      bool exception : 1;
      bool long_jump : 1; // high bit
    };
  };

  friend constexpr bool
  operator&(const BpType &l, const BpType &r) noexcept
  {
    return (l.type & r.type) > 0;
  }

  void
  unset(const BpType &setting) noexcept
  {
    const auto mask = ~(setting.type);
    type &= mask;
  }

  void
  add_setting(const BpType &setting) noexcept
  {
    type |= setting.type;
  }
};

namespace fmt {
template <> struct formatter<BpType>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const BpType &b, FormatContext &ctx)
  {
    std::array<std::string_view, 7> types_names{};
    auto idx = 0u;
    if (b.source) {
      types_names[idx] = "src";
      ++idx;
    }

    if (b.function) {
      types_names[idx] = "fn";
      ++idx;
    }

    if (b.address) {
      types_names[idx] = "addr";
      ++idx;
    }

    if (b.resume_address) {
      types_names[idx] = "resume";
      ++idx;
    }

    if (b.shared_object_load) {
      types_names[idx] = "so";
      ++idx;
    }

    if (b.exception) {
      types_names[idx] = "exception";
      ++idx;
    }

    if (b.long_jump) {
      types_names[idx] = "long_jmp";
      ++idx;
    }

    std::span<std::string_view> types{types_names.begin(), types_names.begin() + idx};

    return fmt::format_to(ctx.out(), "BpType: [ {} ]", fmt::join(types, ", "));
  }
};
} // namespace fmt

enum class BpEventType : u8
{
  // Breakpoints that are visible to the user
  UserBreakpointHit = 1,
  // Breakpoints invisble to user
  TracerBreakpointHit = 2,
  // Breakpoints that are both; meaning they're a tracer breakpoint that shares address
  // with a user set breakpoint.
  Both = 3
};

struct SourceBreakpointDescriptor
{
  std::string_view source_file;
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> condition;
  std::optional<int> hit_condition;
  std::optional<std::string> log_message;

  friend constexpr bool
  operator==(const SourceBreakpointDescriptor &a, const SourceBreakpointDescriptor &b) noexcept
  {
    return a.source_file == b.source_file && a.line == b.line && a.column == b.column;
  }
};

enum class OnBpHit
{
  Continue,
  Stop
};

enum class BpNote
{
  BreakpointHit,
  FinishedFunction
};

class Breakpoint
{
  using TemporaryNotes = std::unordered_map<Tid, BpNote>;
  using StopSet = std::unordered_set<Tid>;

public:
  explicit Breakpoint(AddrPtr, u8 original_byte, u32 id, BpType type) noexcept;
  Breakpoint(Breakpoint &&b) noexcept;
  Breakpoint &operator=(Breakpoint &&) noexcept;
  Breakpoint(const Breakpoint &) noexcept = delete;
  Breakpoint &operator=(const Breakpoint &) noexcept = delete;

  /* Enable this breakpoint. Use `tid` as parameter to ptrace. */
  void enable(Tid tid) noexcept;

  /* Disable this breakpoint. Use `tid` as parameter to ptrace. */
  void disable(Tid tid) noexcept;

  /* Get breakpoint type. */
  BpType type() const noexcept;

  /* Breakpoint logic to perform when hit by Task `t`. */
  OnBpHit on_hit(TraceeController *tc, TaskInfo *t) noexcept;

  /* Check if Task `t` should report stop to user. */
  bool ignore_task(TaskInfo *t) noexcept;

  /* Retrieve stop notification type for this breakpoint, for `t`. */
  BpNote stop_notification(TaskInfo *t) noexcept;

  /* Set default notification type for this breakpoint. */
  void set_note(BpNote) noexcept;

  /* Set temporary notification for this breakpoint, for task `t`. */
  void set_temporary_note(TaskInfo *t, BpNote n) noexcept;

  /* Add `tid` to set of tasks that should be reported to the user when they hit this breakpoint. If no tasks has
   * been registered, all tasks will report stop to user.*/
  void add_stop_for(Tid tid) noexcept;

  // The type of the event this breakpoint will generate
  BpEventType event_type() const noexcept;

  u8 original_byte;
  BpType bp_type;
  u16 id;
  TPtr<void> address;
  bool enabled = true;
  u32 times_hit = 0;
  BpNote on_notify = BpNote::BreakpointHit;
  std::unique_ptr<StopSet> stop_these = nullptr;
  std::unique_ptr<TemporaryNotes> temporary_notes = nullptr;
};

struct BpEvent
{
  BpEventType event;
  union
  {
    AddrPtr pc;
    Breakpoint *bp;
    struct
    {
      AddrPtr var_addr;
      u64 new_value;
    } watchpoint;
  };
};

// Task Breakpoint Status
struct BpStat
{
  u16 bp_id;
  BpType type;
  bool should_resume : 1;
  bool stepped_over : 1;
  bool re_enable_bp : 1;
};

struct BreakpointMap
{
  explicit BreakpointMap(Tid address_space) noexcept
      : address_space_tid(address_space), breakpoints(), fn_breakpoint_names(), source_breakpoints()
  {
  }

  Tid address_space_tid;
  u32 bp_id_counter = 1;
  // All breakpoints are stored in `breakpoints` - and they map to either `fn_breakpoint_names` or
  // `source_breakpoints` depending on their type (or to neither - if they're address breakpoints). So we don't
  // allow for multiple breakpoints on the same loc, because I argue it's a bad decision that makes breakpoint
  // design much more complex for almost 0 gain.
  std::vector<Breakpoint> breakpoints;
  std::unordered_map<u32, std::string> fn_breakpoint_names;
  std::unordered_map<u32, SourceBreakpointDescriptor> source_breakpoints;

  template <typename T>
  bool
  contains(TraceePointer<T> addr) const noexcept
  {
    return any_of(breakpoints, [&addr](const Breakpoint &bp) { return bp.address == addr; });
  }

  bool insert(AddrPtr addr, u8 overwritten_byte, BpType type) noexcept;
  void clear(TraceeController *target, BpType type) noexcept;

  Breakpoint *get_by_id(u32 id) noexcept;
  Breakpoint *get(AddrPtr addr) noexcept;
  void remove_breakpoint(AddrPtr addr, BpType type) noexcept;
};
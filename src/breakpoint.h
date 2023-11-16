#pragma once
#include "common.h"
#include <functional>

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
      bool lsb_padding : 1;
      bool source : 1;
      bool function : 1;
      bool address : 1;
      bool resume_address : 1;
      bool shared_object_load : 1;
      bool exception : 1;
      bool long_jump : 1;
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
    const auto src = b.source;
    const auto fn = b.function;
    const auto addr = b.address;
    const auto resume = b.resume_address;
    const auto so = b.shared_object_load;
    const auto ex = b.exception;
    const auto jmp = b.long_jump;

    return fmt::format_to(ctx.out(),
                          "BpType: [ src: {}, fn: {}, addr: {}, resume: {}, so: {}, exception: {}, long_jmp: {}]",
                          src, fn, addr, resume, so, ex, jmp);
  }
};
} // namespace fmt

enum class BpEventType : u8
{
  UserBreakpointHit = 1,
  TracerBreakpointHit = 2,
  Both = 3,
  None = 4,
};

struct SourceBreakpointDescriptor
{
  std::string_view source_file;
  u32 line;
  std::optional<u32> column;
  std::optional<std::string> condition;
  std::optional<int> hit_condition;
  std::optional<std::string> log_message;
};

class Breakpoint
{
public:
  explicit Breakpoint(AddrPtr, u8 original_byte, u32 id, BpType type) noexcept;
  Breakpoint() noexcept = default;
  Breakpoint(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(const Breakpoint &) noexcept = default;
  Breakpoint &operator=(Breakpoint &&) noexcept = default;

  void enable(Tid tid) noexcept;
  void disable(Tid tid) noexcept;
  BpType type() const noexcept;

  // The type of the event this breakpoint will generate
  BpEventType event_type() const noexcept;

  u8 original_byte;
  BpType bp_type;
  u16 id;
  u32 times_hit;
  TPtr<void> address;
  bool enabled;
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
  bool stepped_over;
};

struct BreakpointMap
{
  explicit BreakpointMap(Tid address_space) noexcept
      : bp_id_counter(1), breakpoints(), address_space_tid(address_space), fn_breakpoint_names(),
        source_breakpoints()
  {
  }

  u32 bp_id_counter;
  // All breakpoints are stored in `breakpoints` - and they map to either `fn_breakpoint_names` or
  // `source_breakpoints` depending on their type (or to neither - if they're address breakpoints). So we don't
  // allow for multiple breakpoints on the same loc, because I argue it's a bad decision that makes breakpoint
  // design much more complex for almost 0 gain.
  std::vector<Breakpoint> breakpoints;
  Tid address_space_tid;
  std::unordered_map<u32, std::string> fn_breakpoint_names;
  std::unordered_map<u32, SourceBreakpointDescriptor> source_breakpoints;

  std::vector<Breakpoint> ld_breakpoints;

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
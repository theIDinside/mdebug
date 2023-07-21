#pragma once
#include "../common.h"
#include "block.h"
#include "dwarf.h"
#include "lnp.h"
#include <optional>
#include <unordered_map>

using AddrRanges = std::vector<AddressRange>;

struct FunctionSymbol
{
  TPtr<void> start;
  TPtr<void> end;
  std::string_view name;
};

/* Included files are files that are not representable as a compilation unit, at least not directly.
To understand why, use `llvm-dwarfdump --debug-info threads` where `threads` is one of the test applications in the
`test/` folder. As we can see, what's generate is 2 compilation units, though we *know* the test application relies
on plenty more (for instance, the name suggests we should be using /std/lib/path/thread.h ). As such
the compilation unit DIE (`DebugInfoEntry`) "owns" these sub files. */
struct IncludedFile
{
  std::string_view file_name;
};

/**
 * Symbol container for a specific file. The idea is that we operate on files when we're a "normal programmer
 * debugger". As such, we want simplicity for the every day case and intuitive behaviors. First design therefore
 * will revolve around compilation units as being a sort of "master identifier"
 */
class CompilationUnitFile
{
public:
  explicit CompilationUnitFile(DebugInfoEntry *cu_die) noexcept;

  Path dir() const noexcept;
  Path source_filename() const noexcept;
  Path fullpath() const noexcept;

  std::string_view name() const noexcept;
  TPtr<void> low_pc() const noexcept;
  TPtr<void> high_pc() const noexcept;
  void set_name(std::string_view name) noexcept;

  void add_addr_rng(const u64 *start) noexcept;

  bool last_added_addr_valid() const noexcept;

  void
  pop_addr() noexcept
  {
    m_addr_ranges.pop_back();
  }

  void set_linetable(LineTable &&lte) noexcept;
  void set_boundaries() noexcept;
  const LineTable &line_table() const noexcept;
  const AddrRanges &address_ranges() const noexcept;

  template <typename T>
  constexpr bool
  may_contain(TPtr<T> ptr) const noexcept
  {
    return pc_boundaries.contains(ptr.as_void());
  }

  void add_function(FunctionSymbol sym) noexcept;
  const FunctionSymbol *find_subprogram(TPtr<void> addr) const noexcept;
  std::vector<AddressRange> m_addr_ranges;

private:
  // the lowest / highest PC in `address_ranges`
  std::string_view m_name;
  AddressRange pc_boundaries;
  LineTable m_ltes;
  std::vector<FunctionSymbol> fns;
  DebugInfoEntry *cu_die;
};

namespace fmt {
template <> struct formatter<CompilationUnitFile>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(CompilationUnitFile const &f, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{{ path: {}, low: {}, high: {}, blocks: {} }}", f.name(), f.low_pc(),
                          f.high_pc(), f.address_ranges().size());
  }
};

} // namespace fmt
#pragma once
#include "../common.h"
#include "block.h"
#include "dwarf.h"
#include "dwarf_frameunwinder.h"
#include "lnp.h"
#include <optional>
#include <unordered_map>

using AddrRanges = std::vector<AddressRange>;

class Elf;

struct FunctionSymbol
{
  AddrPtr start;
  AddrPtr end;
  std::string_view name;
  sym::UnwindInfo unwind;
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
 * These CU's represent compilation units that contain executable code. CU's that don't, or that contain references
 * to other CU's that may or may not, is instead called NonExecutableCompilationUnitFile. This way they won't
 * clutter up the containers so searching for code addresses can be kept as fast as possible, even without
 * optimizations.
 */
class CompilationUnitFile
{
public:
  explicit CompilationUnitFile(DebugInfoEntry *cu_die, const Elf *elf) noexcept;
  CompilationUnitFile(CompilationUnitFile &&o) noexcept;
  CompilationUnitFile &operator=(CompilationUnitFile &&) noexcept;
  NO_COPY(CompilationUnitFile);

  Path dir() const noexcept;
  Path source_filename() const noexcept;
  Path fullpath() const noexcept;

  std::string_view name() const noexcept;
  AddrPtr low_pc() const noexcept;
  AddrPtr high_pc() const noexcept;
  void set_name(std::string_view name) noexcept;

  void add_addr_rng(const u64 *start) noexcept;
  void add_addr_rng(AddrPtr start, AddrPtr end) noexcept;

  bool last_added_addr_valid() const noexcept;

  void
  pop_addr() noexcept
  {
    m_addr_ranges.pop_back();
  }

  void set_linetable(const LineHeader *header) noexcept;
  bool known_addresses() const noexcept;
  void set_boundaries() noexcept;
  const LineTable &line_table() const noexcept;
  const AddrRanges &address_ranges() const noexcept;
  AddressRange low_high_pc() const noexcept;

  template <typename T>
  constexpr bool
  may_contain(TPtr<T> ptr) const noexcept
  {
    return pc_boundaries.contains(ptr);
  }

  void add_function(FunctionSymbol sym) noexcept;
  const FunctionSymbol *find_subprogram(AddrPtr addr) const noexcept;
  LineTableEntryRange get_range(AddrPtr addr) const noexcept;
  LineTableEntryRange get_range(AddrPtr start, AddrPtr end) const noexcept;
  LineTableEntryRange get_range_of_pc(AddrPtr addr) const noexcept;
  std::string_view file(u32 index) const noexcept;
  std::string_view path_of_file(u32 index) const noexcept;
  Path file_path(u32 index) const noexcept;
  std::vector<AddressRange> m_addr_ranges;

private:
  // the lowest / highest PC in `address_ranges`
  std::string_view m_name;
  AddressRange pc_boundaries;
  const LineHeader *line_header;
  std::vector<FunctionSymbol> fns;
  DebugInfoEntry *cu_die;
  const Elf *elf;
};

class NonExecutableCompilationUnitFile
{
  DebugInfoEntry *partial_cu_die;
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
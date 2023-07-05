#pragma once
#include "../common.h"
#include "block.h"
#include "lnp.h"
#include <optional>

using AddrRanges = std::vector<AddressRange>;
struct Field
{
  const char *name;
  u32 offset;
  u32 size;
};

struct Type
{
  std::string_view name;
  std::vector<Field> members;
  u64 size_of() const noexcept;
};

struct Symbol
{
  const char *name;
  Type type;
  TPtr<void> address;
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
  explicit CompilationUnitFile(std::string_view name, AddrRanges &&addr_ranges, LineTable &&lt_ents) noexcept;

  Path dir() const noexcept;
  Path source_filename() const noexcept;

  std::string_view name() const noexcept;
  TPtr<void> low_pc() const noexcept;
  TPtr<void> high_pc() const noexcept;
  const LineTable &line_table() const noexcept;
  const AddrRanges &address_ranges() const noexcept;

  template <typename T>
  bool
  may_contain(TPtr<T> ptr) const noexcept
  {
    return pc_boundaries.contains(ptr.as_void());
  }

private:
  // the lowest / highest PC in `address_ranges`
  std::string_view m_name;
  std::vector<AddressRange> m_addr_ranges;
  LineTable m_ltes;
  // The lowest (inclusive) and highest (exclusive) pc in this CU's range (`m_addr_ranges`)
  AddressRange pc_boundaries;
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
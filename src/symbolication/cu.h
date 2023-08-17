#pragma once

#include "cu_file.h"
#include "dwarf.h"
#include "lnp.h"
#include "objfile.h"
#include <concepts>
#include <cstddef>
#include <cstring>
#include <optional>
#include <type_traits>
#include <utility>
class CompilationUnitFile;

/**
 * The processed Compilation Unit Header. For the raw byte-to-byte representation see D4/D5
 */
struct CompileUnitHeader
{
  u64 length;
  u64 abbrev_offset;
  const u8 *data;
  const u8 *end;
  u32 cu_index;
  u64 debug_info_sec_offset;
  u8 addr_size;
  u8 format;
  DwarfVersion version;
  u8 header_length;
};

class CompileUnitReader
{
public:
  const ObjectFile *obj_file;

public:
  CompileUnitReader(CompileUnitHeader *header, const ObjectFile *obj_file) noexcept;

  UnrelocatedTraceePointer read_address() noexcept;
  std::string_view read_string() noexcept;
  DataBlock read_block(u64 size) noexcept;
  u64 bytes_read() const noexcept;

  /// Needs to be auto, otherwise we are not widening the value
  template <std::integral Integral>
  constexpr auto
  read_integral() noexcept
  {
    Integral type = *(Integral *)current_ptr;
    current_ptr += sizeof(Integral);
    if constexpr (std::unsigned_integral<Integral>) {
      return static_cast<u64>(type);
    } else if constexpr (std::signed_integral<Integral>) {
      return static_cast<i64>(type);
    } else {
      static_assert(always_false<Integral>,
                    "Somehow, some way, an integral slipped through that's neither signed nor unsigned");
    }
  }

  u64 uleb128() noexcept;
  i64 leb128() noexcept;
  u64 read_offset() noexcept;
  bool has_more() const noexcept;
  u64 read_section_offset(u64 offset) const noexcept;
  u64 read_bytes(u8 bytes) noexcept;
  UnrelocatedTraceePointer read_by_idx_from_addr_table(u64 address_index) const noexcept;
  std::string_view read_by_idx_from_str_table(u64 str_index) const noexcept;
  u64 read_by_idx_from_rnglist(u64 range_index) const noexcept;
  u64 read_loclist_index(u64 range_index) const noexcept;
  u64 sec_offset() const noexcept;

private:
  CompileUnitHeader *header;
  const u8 *current_ptr;
  std::optional<u64> addr_table_base;
  std::optional<u64> str_offsets_base;
  std::optional<u64> rng_list_base;
  std::optional<u64> loc_list_base;
};

/**
 * Processes a single CU after having decoded the abbreviation table for it.
 * This type can be considered a "thread unit of work". It's safe to send off to a thread somewhere
 * because all the jobs it do, it does on it's own. At least that's the idea.
 * Any DWARF references between compilation units, will be resolved _after_ each CUProcessor has finished
 * at which point, we could, create a new type that shares some of the behaviors of CUProcessors, being an
 * "independent job/task/thread". The idea is to try to find where/when/if what parts of DWARF is trivially
 * parallelizable and design our debugger *specifically* with that in mind. We're not there yet though, by a long
 * shot, as to find these trivially parallell solutions, we must first have a naive one.
 */
class CUProcessor
{
  // todo(simon): Layout of type
  // todo(simon): Redundancy?
  // todo(simon): Data ownership?
public:
  CUProcessor(ObjectFile *obj_file, CompileUnitHeader header, AbbreviationInfo::Table &&table, u32 index,
              TraceeController *target) noexcept;
  CUProcessor(CUProcessor &&) noexcept = default;
  CUProcessor(const CUProcessor &) = delete;

  std::unique_ptr<DebugInfoEntry> read_dies() noexcept;
  const CompileUnitHeader &get_header() const noexcept;
  LineHeader *get_lnp_header() const noexcept;
  void process_compile_unit_die(DebugInfoEntry *cu_die) noexcept;
  std::optional<AddressRange> determine_unrelocated_bounds(DebugInfoEntry *die) const noexcept;
  AddrPtr reloc_base() const noexcept;

private:
  bool finished;
  std::string_view file_name;
  ObjectFile *obj_file;
  u32 cu_index;
  CompileUnitHeader header;
  AbbreviationInfo::Table abbrev_table;
  std::vector<DebugInfoEntry> cu_dies;
  std::unique_ptr<CompilationUnitFile> cu_file;
  // The Target that is requesting parsing of debug info
  TraceeController *requesting_target;
  std::unique_ptr<LineHeader> line_header;
  OwnedLineTable line_table;
};

namespace fmt {
template <> struct formatter<CompileUnitHeader>
{
  template <typename ParseContext> constexpr auto parse(ParseContext &ctx);

  template <typename FormatContext> auto format(CompileUnitHeader const &item, FormatContext &ctx);
};

template <typename ParseContext>
constexpr auto
formatter<CompileUnitHeader>::parse(ParseContext &ctx)
{
  return ctx.begin();
}

template <typename FormatContext>
auto
formatter<CompileUnitHeader>::format(CompileUnitHeader const &item, FormatContext &ctx)
{
  return fmt::format_to(ctx.out(),
                        "Compile Unit: length = {:#010x}, format = {}, version = {:#06x}, abbr_offset = "
                        "{:#06x}, addr_size = {:#04x}",
                        item.length, "DWARF32", std::to_underlying(item.version), item.abbrev_offset, 8);
}

}; // namespace fmt

struct DetermineDwarf
{
  union
  {
    struct
    {
      u32 length;
      u16 version;
    } dw32;
    struct
    {
      u32 dummy;
      u64 length;
      u16 version;
    } dw64;
  };
  bool
  is_32() const noexcept
  {
    return dw32.length != 0xff'ff'ff'ff;
  }

  bool
  is_64() const noexcept
  {
    return dw64.dummy == 0xff'ff'ff'ff;
  }

  u16
  version() const noexcept
  {
    if (is_32())
      return dw32.version;
    else
      return dw64.version;
  }
};

#pragma pack(push, 1)
template <UnsignedWord T> struct D4 : InitialLength<T>
{
  static constexpr auto
  version() noexcept
  {
    return DwarfVersion::D4;
  }
  static constexpr auto
  len_offset() noexcept
  {
    return offsetof(InitialLength<T>, len);
  }
  T abbr_offset;
  u8 addr_size;
};

template <UnsignedWord T> struct D5 : InitialLength<T>
{
  static constexpr auto
  version() noexcept
  {
    return DwarfVersion::D5;
  }
  static constexpr auto
  len_offset() noexcept
  {
    return offsetof(InitialLength<T>, len);
  }
  u8 unit_type;
  u8 addr_size;
  T abbr_offset;
};
#pragma pack(pop)
// clang-format off
template <typename Header>
concept CUHeader = requires(Header header) {
  { header.ver } -> std::convertible_to<u64>;
  { header.addr_size } -> std::convertible_to<u64>;
  { header.abbr_offset } -> std::convertible_to<u64>;
  { header.len } -> std::convertible_to<u64>;
  { header.addr_size } -> std::convertible_to<u64>;
  { Header::version() };
  { Header::len_offset() } -> std::convertible_to<u64>;
};
// clang-format on

// Assume a few things; once the version and address size
// has been read, we never read it again. Share that data amongst
// all CU's of an OBJFILE
class CompilationUnitBuilder
{
public:
  explicit CompilationUnitBuilder(ObjectFile *obj_file) noexcept;
  std::vector<CompileUnitHeader> build_cu_headers() noexcept;

private:
  template <CUHeader DwarfSpec>
  std::vector<CompileUnitHeader>
  build_cu_headers_impl() noexcept
  {

    const auto dbg_info = obj_file->parsed_elf->debug_info;
    std::vector<CompileUnitHeader> result{};
    auto it = dbg_info->begin();
    auto end = dbg_info->end();
    u32 cu_index = 1;
    while (it < end) {
      auto cu_hdr = (DwarfSpec *)it;
      CompileUnitHeader header{.length = cu_hdr->len,
                               .abbrev_offset = cu_hdr->abbr_offset,
                               .data = it + sizeof(DwarfSpec),
                               .end = it + cu_hdr->len + (sizeof(cu_hdr->len) + DwarfSpec::len_offset()),
                               .cu_index = cu_index,
                               .debug_info_sec_offset = dbg_info->get_ptr_offset(it),
                               .addr_size = cu_hdr->addr_size,
                               .format = DwarfSpec::len_offset() + 4,
                               .version = DwarfSpec::version(),
                               .header_length = sizeof(DwarfSpec)};
      result.push_back(header);
      it = result.back().end;
      cu_index++;
    }
    return result;
  }

private:
  ObjectFile *obj_file;
};
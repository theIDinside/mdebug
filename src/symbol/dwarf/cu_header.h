#pragma once

// SYMBOLS DWARF namespace
namespace sym::dw {
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

} // namespace sym::dw

namespace fmt {
using CUHeader = sym::dw::CompileUnitHeader;
template <> struct formatter<CUHeader>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const CUHeader &item, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(),
                          "Compile Unit: length = {:#010x}, format = {}, version = {:#06x}, abbr_offset = "
                          "{:#06x}, addr_size = {:#04x}",
                          item.length, "DWARF32", std::to_underlying(item.version), item.abbrev_offset, 8);
  }
};

}; // namespace fmt
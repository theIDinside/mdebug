#pragma once
#include "die.h"

class Elf;
struct ObjectFile;

namespace sym::dw {
class UnitReader
{
public:
  UnitReader(UnitData *data) noexcept;
  void skip_attributes(const std::span<const Abbreviation> &attributes) noexcept;
  UnrelocatedTraceePointer read_address() noexcept;
  std::string_view read_string() noexcept;
  DataBlock read_block(u64 block_size) noexcept;
  u64 bytes_read() const noexcept;

  u64 uleb128() noexcept;
  i64 leb128() noexcept;

  LEB128Read<u64> read_uleb128() noexcept;
  LEB128Read<i64> read_leb128() noexcept;
  u64 read_offset() noexcept;
  u64 read_section_offset(u64 offset) const noexcept;
  u64 read_n_bytes(u8 n_bytes) noexcept;
  UnrelocatedTraceePointer read_by_idx_from_addr_table(u64 address_index,
                                                       std::optional<u64> addr_table_base) const noexcept;
  std::string_view read_by_idx_from_str_table(u64 str_index, std::optional<u64> str_offsets_base) const noexcept;
  u64 read_by_idx_from_rnglist(u64 range_index, std::optional<u64> rng_list_base) const noexcept;
  u64 read_loclist_index(u64 range_index, std::optional<u64> loc_list_base) const noexcept;
  u64 sec_offset() const noexcept;
  bool has_more() const noexcept;

  /* Set UnitReader to start reading the data for `entry` */
  void seek_die(const DieMetaData &entry) noexcept;
  ObjectFile *objfile() const noexcept;
  Elf *elf() const noexcept;
  const u8 *ptr() const noexcept;

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

private:
  UnitData *compilation_unit;
  const u8 *current_ptr;
};
} // namespace sym::dw
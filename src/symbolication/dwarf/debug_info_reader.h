#pragma once
#include "../dwarf_defs.h"
#include "die.h"
#include <common.h>
#include <typedefs.h>

class Elf;
class ObjectFile;

struct AttributeValue;

namespace sym::dw {

class UnitData;
struct Abbreviation;
struct DieMetaData;

class UnitReader
{
public:
  explicit UnitReader(UnitData *data) noexcept;
  UnitReader(UnitData *data, const DieMetaData &entry) noexcept;
  UnitReader(UnitData *data, u64 offset) noexcept;
  UnitReader(const UnitReader &o) noexcept;
  UnitReader &operator=(const UnitReader &reader) noexcept;

  void skip_attributes(const std::span<const Abbreviation> &attributes) noexcept;
  void skip_attribute(const Abbreviation &abbreviation) noexcept;
  AddrPtr read_address() noexcept;
  std::string_view read_string() noexcept;
  const char *ReadCString() noexcept;
  DataBlock read_block(u64 block_size) noexcept;
  u64 bytes_read() const noexcept;

  u64 uleb128() noexcept;
  i64 leb128() noexcept;

  LEB128Read<u64> read_uleb128() noexcept;
  LEB128Read<i64> read_leb128() noexcept;
  u64 read_offset() noexcept;
  u64 read_section_offset(u64 offset) const noexcept;
  u64 read_n_bytes(u8 n_bytes) noexcept;
  AddrPtr read_by_idx_from_addr_table(u64 address_index) const noexcept;
  const char *read_by_idx_from_str_table(u64 str_index) const noexcept;
  u64 read_by_idx_from_rnglist(u64 range_index) const noexcept;
  u64 read_loclist_index(u64 range_index, std::optional<u64> loc_list_base) const noexcept;
  u64 sec_offset() const noexcept;
  bool has_more() const noexcept;

  /* Set UnitReader to start reading the data for `entry` */
  void SeekDie(const DieMetaData &entry) noexcept;
  void SetOffset(u64 offset) noexcept;
  ObjectFile *objfile() const noexcept;
  const Elf *elf() const noexcept;
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
  inline constexpr u64
  Format() const noexcept
  {
    return mFormat;
  }

  inline constexpr u64
  AddressSize() const noexcept
  {
    return 8;
  }

  UnitData *compilation_unit;
  const u8 *current_ptr;
  u8 mFormat;
};

AttributeValue read_attribute_value(UnitReader &reader, Abbreviation abbr,
                                    const std::vector<i64> &implicit_consts) noexcept;

class DieAttributeReader
{
  DieReference die;
  const AbbreviationInfo &info;

public:
  DieAttributeReader(DieReference die, const AbbreviationInfo &info) noexcept;
};

} // namespace sym::dw
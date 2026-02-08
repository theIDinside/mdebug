/** LICENSE TEMPLATE */
#pragma once
#include "../dwarf_defs.h"
#include "die.h"
#include <common.h>
#include <common/typedefs.h>

namespace mdb {
class Elf;
class ObjectFile;
struct AttributeValue;
} // namespace mdb

namespace mdb::sym::dw {

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

  // Skip a computec offset in the byte stream we are reading from by determining
  // the total amount of bytes that `attributes` would consist of
  void SkipAttributes(const std::span<const Abbreviation> &attributes) noexcept;
  // See `SkipAttributes` but for 1
  void SkipAttribute(const Abbreviation &abbreviation) noexcept;

  AddrPtr ReadAddress() noexcept;
  std::string_view ReadString() noexcept;
  const char *ReadCString() noexcept;
  DataBlock ReadBlock(u64 block_size) noexcept;
  u64 BytesRead() const noexcept;

  u64 ReadULEB128() noexcept;
  i64 ReadLEB128() noexcept;

  // Read* functions just reads the U/LEB128 value. Decode* functions
  // read the value and also returns the amount of bytes that was needed to parse for that value.
  LEB128Read<u64> DecodeULEB128() noexcept;
  LEB128Read<i64> DecodeLEB128() noexcept;
  u64 ReadOffsetValue() noexcept;
  u64 ReadSectionOffsetValue(u64 offset) const noexcept;
  u64 ReadNumbBytes(u8 bytes) noexcept;
  AddrPtr ReadByIndexFromAddressTable(u64 addressIndex) const noexcept;
  const char *ReadByIndexFromStringTable(u64 strIndex) const noexcept;
  u64 ReadByIndexFromRangeList(u64 rangeIndex) const noexcept;
  u64 ReadLocationListIndex(u64 rangeIndex, std::optional<u64> locListBase) const noexcept;
  u64 SectionOffset() const noexcept;
  bool HasMore() const noexcept;

  /* Set UnitReader to start reading the data for `entry` */
  void SeekDie(const DieMetaData &entry) noexcept;
  void SetOffset(u64 offset) noexcept;
  /// Return the `ObjectFile` that UnitReader is reading a compilation unit from.
  ObjectFile *GetObjectFile() const noexcept;
  const Elf *GetElf() const noexcept;
  const u8 *RawPointer() const noexcept;

  /// Needs to be auto, otherwise we are not widening the value
  template <std::integral Integral>
  constexpr auto
  ReadIntegralValue() noexcept
  {
    Integral tmp;
    constexpr auto size = sizeof(Integral);
    std::memcpy(&tmp, mCurrentPtr, size);
    mCurrentPtr += size;
    // Always return 8 byte values, because this simplifies *a lot*
    if constexpr (std::unsigned_integral<Integral>) {
      return static_cast<u64>(tmp);
    } else if constexpr (std::signed_integral<Integral>) {
      return static_cast<i64>(tmp);
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

  UnitData *mCompilationUnit;
  const u8 *mCurrentPtr;
  u8 mFormat;
};

AttributeValue ReadAttributeValue(
  UnitReader &reader, Abbreviation abbr, const std::vector<i64> &implicit_consts) noexcept;

class DieAttributeReader
{
  DieReference die;
  const AbbreviationInfo &info;

public:
  DieAttributeReader(DieReference die, const AbbreviationInfo &info) noexcept;
};

} // namespace mdb::sym::dw
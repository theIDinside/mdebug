#pragma once

#include "../common.h"
#include "dwarf_defs.h"
#include <optional>
#include <type_traits>
#include <utility>

struct ObjectFile;
struct CompileUnitHeader;
class CUProcessor;
struct TraceeController;

// Decodes values in abbreviation table for CU described by `header` (but does not translate them)
std::unique_ptr<CUProcessor> prepare_cu_processing(ObjectFile *obj_file, const CompileUnitHeader &header,
                                                   TraceeController *target);

template <typename T> concept UnsignedWord = std::is_same_v<T, u32> || std::is_same_v<T, u64>;

#pragma pack(push, 1)
template <bool Dummy> struct dummy
{
};

template <> struct dummy<true>
{
  u32 _dummy;
};

template <UnsignedWord T> struct InitialLength
{
  [[no_unique_address]] dummy<std::is_same_v<T, u64>> dummy;
  T len;
  u16 ver;
};
#pragma pack(pop)

struct Abbreviation
{
  Attribute name;
  AttributeForm form;
  // An index into a IMPLICIT_CONST table for this abbreviation table
  // This is solely done for space reasons, instead of paying the cost of 64 bits for every
  // Abbreviation. Let's hope that only 255 implicit consts exist within each abbrev table.
  u8 IMPLICIT_CONST_INDEX;
};

struct AbbreviationInfo
{
  /// Describes a table of `AbbreviationInfo`. Abbreviation codes increase monotonically and are 1-indexed
  /// as such a hash map is not required here; just perform arithmetic (-1) and look-up by index.
  using Table = std::vector<AbbreviationInfo>;
  // The abbreviation code
  u32 code;
  DwarfTag tag;
  bool has_children;
  u32 sibling_offset;
  std::vector<Abbreviation> attributes;
  std::vector<i64> implicit_consts;
};

struct StrSlice
{
  const char *ptr;
  u64 size;
};

#define ATTR_CTOR(DataType, field)                                                                                \
  constexpr AttributeValue(DataType data, AttributeForm form, Attribute name) noexcept                            \
      : form{form}, name{name}, value{data}                                                                       \
  {                                                                                                               \
  }

template <typename T>
concept AttributeValueType = std::is_same_v<T, u64> || std::is_same_v<T, i64> || std::is_same_v<T, DataBlock> ||
                             std::is_same_v<T, StrSlice> || std::is_same_v<T, std::string_view> ||
                             std::is_same_v<T, UnrelocatedTraceePointer>;

/** Fully-formed attribtue */
struct AttributeValue
{
  template <AttributeValueType T>
  constexpr AttributeValue(T value, AttributeForm form, Attribute name) noexcept
      : form{form}, name{name}, value{value}
  {
  }

  std::uintptr_t address() const noexcept;
  std::string_view string() const noexcept;
  DataBlock block() const noexcept;
  u64 unsigned_value() const noexcept;
  i64 signed_value() const noexcept;
  AttributeForm form;
  Attribute name;

private:
  union _value
  { // Size = 16 bytes
    constexpr _value(std::string_view str) noexcept : str{str} {}
    constexpr _value(DataBlock block) noexcept : block(block) {}
    constexpr _value(u64 u) noexcept : u(u) {}
    constexpr _value(i64 i) noexcept : i(i) {}
    constexpr _value(UnrelocatedTraceePointer ptr) noexcept : addr(ptr) {}

    DataBlock block;
    // StrSlice str;
    std::string_view str;
    u64 u;
    i64 i;
    UnrelocatedTraceePointer addr;
  } value;
};

struct DebugInfoEntry
{
  u32 abbreviation_code;
  DwarfTag tag;
  bool subprogram_with_addresses;
  u32 sec_offset;

  // todo(simon): Make this better.
  // This is terrible for performance. But it's easy. The reason being
  // is that the layout is terrible, we have:
  // root, 1st child, (1st child (1st child ... siblings) .. siblings), which mean we can't iterate over contigous
  // memory, if we only want to iterate over the direct children of the root.
  std::vector<std::unique_ptr<DebugInfoEntry>> children;

  std::vector<AttributeValue> attributes;

  void debug_dump(int indent = 0) const noexcept;
  void set_abbreviation(const AbbreviationInfo &a) noexcept;
  void set_offset(u64 sec_offset) noexcept;
  std::optional<AttributeValue> get_attribute(Attribute attr) const noexcept;

private:
  constexpr void
  set_tag(DwarfTag tag) noexcept
  {
    this->tag = tag;
    subprogram_with_addresses = (tag == DwarfTag::DW_TAG_subprogram || tag == DwarfTag::DW_TAG_subroutine_type);
  }
};

/// DWARF version >= 5
struct AddressTableHeader32
{
  u32 len;
  u16 version;
  u8 addr_size;
  u8 segment_selector_size;
};

struct AddressTableHeader64
{
  u32 dummy;
  u64 len;
  u16 version;
  u8 addr_size;
  u8 segment_selector_size;
};

struct RangeListTableHeader32
{
  u32 len;
  u16 version;
  u8 address_size;
  u8 segment_selector_size;
  u32 offset_entry_count;
};

struct RangeListTableHeader64
{
  u32 dummy;
  u64 len;
  u16 version;
  u8 address_size;
  u8 segment_selector_size;
  u32 offset_entry_count;
};

using LocationListTableHeader32 = RangeListTableHeader32;
using LocationListTableHeader64 = RangeListTableHeader64;

struct StringOffsetsTable32
{
  u32 len;
  u16 version;
  u16 padding;
};

struct StringOffsetsTable64
{
  u32 dummy;
  u64 len;
  u16 version;
  u16 padding;
};

struct AddressRangeTable32
{
  u32 len;
  u16 version;
  u32 debug_info_offset;
  u8 address_size;
  u8 segment_selector_size;
};

struct AddressRangeTable64
{
  u32 dummy;
  u64 len;
  u16 version;
  u64 debug_info_offset;
  u8 address_size;
  u8 segment_selector_size;
};
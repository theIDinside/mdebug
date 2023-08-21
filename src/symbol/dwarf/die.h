#pragma once
#include "dwarf_defs.h"
#include <common.h>

// SYMBOLS DWARF namespace
namespace sym::dw {

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

#define ATTR_CTOR(DataType, field)                                                                                \
  constexpr AttributeValue(DataType data, AttributeForm form, Attribute name) noexcept                            \
      : form{form}, name{name}, value{data}                                                                       \
  {                                                                                                               \
  }

template <typename T>
concept AttributeValueType = std::is_same_v<T, u64> || std::is_same_v<T, i64> || std::is_same_v<T, DataBlock> ||
                             std::is_same_v<T, std::string_view> || std::is_same_v<T, UnrelocatedTraceePointer>;

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

}; // namespace sym::dw
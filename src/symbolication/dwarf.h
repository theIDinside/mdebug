#pragma once

#include "../common.h"
#include "dwarf_defs.h"
#include <optional>
#include <type_traits>
#include <utility>

struct ObjectFile;
struct CompileUnitHeader;
class CUProcessor;
struct Target;

// Decodes values in abbreviation table for CU described by `header` (but does not translate them)
std::unique_ptr<CUProcessor> prepare_cu_processing(ObjectFile *obj_file, const CompileUnitHeader &header,
                                                   Target *target);

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

enum class DwarfVersion : u8
{
  D2 = 2,
  D3 = 3,
  D4 = 4,
  D5 = 5,
};

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
  constexpr AttributeValue(DataType data, AttributeForm form, Attribute name,                                     \
                           bool requires_more = false) noexcept                                                   \
      : form{form}, name{name}, requires_more_context(requires_more), value{data}                                 \
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
  constexpr AttributeValue(T value, AttributeForm form, Attribute name, bool requires_more = false) noexcept
      : form{form}, name{name}, requires_more_context(requires_more), value{value}
  {
  }

  std::uintptr_t address() const noexcept;
  std::string_view string() const noexcept;
  DataBlock block() const noexcept;
  u64 unsigned_value() const noexcept;
  i64 signed_value() const noexcept;
  AttributeForm form;
  Attribute name;
  // For AttributeValue's where the payload (data in the union)
  // requires additional context to be fully realized / interpreted.
  bool requires_more_context;

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
  /** Offset into .debug_info or .debug_types */
  u64 next_die_in_cu;
  DebugInfoEntry *first_child;
  DebugInfoEntry *next_sibling;
  DebugInfoEntry *parent;
  DwarfTag tag;
  std::vector<AttributeValue> attributes;
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

/**
 * LNP V4
 */
// unit_length                          4/12 bytes
// version                              2 bytes
// header_length                        4/8 bytes     - number of bytes, starting from `min_ins_len` to where data
// begins min_ins_len                          1 byte maximum_operations_per_instruction   1 byte default_is_stmt
// 1 byte line_base                            1 signed byte line_range                           1 byte
// opcode_base                          1 byte
// standard_opcode_lengths              (array of byte)
// include_directories                  (array of sequence of bytes (as string))
// file_names                           (array of sequence of bytes (as string))

struct DirEntry
{
  std::string_view path;
  std::optional<DataBlock> md5;
};

struct FileEntry
{
  std::string_view file_name;
  u64 dir_index;
  std::optional<u64> file_size;
  std::optional<DataBlock> md5;
};

/**
 * The processed Line Number Program Header. For the raw byte-to-byte representation see LineHeader4/5
 */
struct LineHeader
{
  using DirEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  using FileNameEntFormats = std::vector<std::pair<LineNumberProgramContent, AttributeForm>>;
  u64 length;
  const u8 *data;
  DwarfVersion version;
  u8 addr_size;
  u8 segment_selector_size;
  u8 min_ins_length4;
  u8 max_ops_per_ins;
  bool default_is_stmt;
  i8 line_base;
  u8 line_range;
  u8 opcode_base;
  std::array<u8, std::to_underlying(LineNumberProgramOpCode::DW_LNS_set_isa)> std_opcode_lengths;
  std::vector<DirEntry> directories;
  std::vector<FileEntry> file_names;
};

std::unique_ptr<LineHeader> read_lineheader_v5(const u8 *bytes) noexcept;
std::unique_ptr<LineHeader> read_lineheader_v4(const u8 *ptr) noexcept;
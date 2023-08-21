#pragma once

#include "../common.h"

struct TraceeController;

// SYMBOLS namespace
namespace sym {
struct ObjectFile;

namespace dw {
struct CompileUnitHeader;
class CUProcessor;
} // namespace dw

// Decodes values in abbreviation table for CU described by `header` (but does not translate them)
std::unique_ptr<dw::CUProcessor> prepare_cu_processing(ObjectFile *obj_file, const dw::CompileUnitHeader &header,
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
}; // namespace sym
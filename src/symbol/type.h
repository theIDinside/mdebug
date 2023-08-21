#pragma once
#include "cu_file.h"
#include "dwarf/dwarf_defs.h"
#include <common.h>
#include <stack>
#include <string_view>

namespace sym {

namespace dw {
struct DebugInfoEntry;
}

class Type;
using TypeMap = std::unordered_map<u64, sym::Type>;
using NameTypeMap = std::unordered_map<std::string_view, u64>;
using Bytes = std::vector<u8>;

enum class TypeEncoding : u8
{
  Structure = 0,
  ADT = 1,
  Enum = 2,
  BaseType = 3
};

class Type;

// Fields are: member variables, member functions, etc
struct Field
{
  std::string_view name;
  u64 offset_of;
  u64 field_index;
  Type *type;
};

// This is meant to be the interface via which we interpret a range of bytes
class Type
{
public:
  Type(std::string_view name) noexcept;
  Type(Type &&o) noexcept;
  void set_field_count(u32 cnt) noexcept;
  void set_field(Field field, u32 index) noexcept;
  void set_type_code(TypeEncoding enc) noexcept;

  std::string_view name;
  u32 size_of;
  BaseTypeEncoding base_type;
  TypeEncoding type_code;
  std::vector<Field> fields;
  bool resolved;
  dw::DebugInfoEntry *die;
};

class Value
{
public:
  Value(Type *type, Bytes &&bytes) noexcept;

private:
  Type *type;
  std::vector<u8> bytes;
};

class TypeReader
{
public:
  TypeReader(u64 dbg_inf_start_offs, TypeMap &storage, const dw::DebugInfoEntry *type) noexcept;
  auto read_in() noexcept -> void;

private:
  auto read_type_from_signature() noexcept -> void;
  auto read_structured() noexcept -> void;
  auto read_primitive() noexcept -> void;
  auto sec_offset(const dw::DebugInfoEntry *ent) noexcept -> u64;

  [[gnu::always_inline]] inline auto current() noexcept -> const dw::DebugInfoEntry *;

  u64 dbg_inf_start_offs;
  TypeMap &storage;
  const dw::DebugInfoEntry *root;
  std::stack<const dw::DebugInfoEntry *> curr_stack;
};

void read_type_from_signature(u64 dbg_inf_start_offs, TypeMap &storage, u64 type_signature,
                              const dw::DebugInfoEntry *die) noexcept;
void read_structured(u64 dbg_inf_start_offs, TypeMap &storage, const dw::DebugInfoEntry *die) noexcept;
void read_type(u64 dbg_inf_start_offs, TypeMap &storage, const dw::DebugInfoEntry *die) noexcept;

} // namespace sym
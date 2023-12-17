#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include "symbolication/dwarf/die.h"
#include <stack>
#include <string_view>

struct DebugInfoEntry;

namespace sym {

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
  dw::IndexedDieReference die_ref;
};

class Value
{
public:
  Value(Type *type, Bytes &&bytes) noexcept;

private:
  Type *type;
  std::vector<u8> bytes;
};

} // namespace sym
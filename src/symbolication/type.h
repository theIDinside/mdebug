#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include "fmt/core.h"
// #include "symbolication/dwarf/die.h"
#include "task.h"
#include "utils/byte_buffer.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/indexing.h"
#include "utils/macros.h"
#include <symbolication/dwarf/die_ref.h>

struct DebugInfoEntry;
struct TraceeController;
struct ObjectFile;

namespace sym {
class Type;
class Frame;

using TypeMap = std::unordered_map<u64, Type>;
using NameTypeMap = std::unordered_map<std::string_view, u64>;

namespace dw {
class TypeSymbolicationContext;
struct DieMetaData;
}; // namespace dw

} // namespace sym

class TypeStorage
{
  std::mutex m;
  std::unordered_map<u64, sym::Type *> types;
  ObjectFile &obj;

public:
  TypeStorage(ObjectFile &obj) noexcept;
  ~TypeStorage() noexcept;

  /** Search for a type that has type_id with the section offset specified by die_ref (indirectly, one must
   * retrieve DieMetaData for it first). If the type exists that type is returned, if it is not, a new type is
   * prepared and then that is returned. In DWARF, unfortunately, there are types for const Foo, Foo*, Foo& etc,
   * and they all have an additional level of indirection, pointing to the "Foo" class type/struct type die.
   * This has multiple problems, first of all, when we run into a Foo*, we must make sure that Foo also exist
   * before we return Foo* here, because the target type will be defined by Foo. */
  sym::Type *get_or_prepare_new_type(sym::dw::IndexedDieReference die_ref) noexcept;
  sym::Type *get_unit_type() noexcept;
  sym::Type *emplace_type(Offset type_id, sym::dw::IndexedDieReference die_ref, u32 type_size,
                          std::string_view name) noexcept;
};

namespace sym {

enum class LocKind : u8
{
  DwarfExpression,
  AbsoluteAddress,
  OffsetOf
};

struct SymbolLocation
{
  LocKind kind;
  union
  {
    std::span<const u8> dwarf_expr;
    AddrPtr remote_target;
    u32 offset_of;
  };

  static constexpr auto
  Expression(std::span<const u8> expr) noexcept
  {
    return SymbolLocation{.kind = LocKind::DwarfExpression, .dwarf_expr = expr};
  }

  static constexpr auto
  AbsoluteAddress(AddrPtr addr)
  {
    return SymbolLocation{.kind = LocKind::AbsoluteAddress, .remote_target = addr};
  }

  static constexpr auto
  OffsetOf(u32 offset_of)
  {
    return SymbolLocation{.kind = LocKind::OffsetOf, .offset_of = offset_of};
  }
};

// Fields are: member variables, member functions, etc
struct Field
{
  NonNullPtr<Type> type;
  Immutable<u32> offset_of;
  Immutable<std::string_view> name;
};

template <typename To, typename From>
constexpr auto
bit_copy_from(From from) -> To
{
  static_assert(std::is_trivial_v<To>, "Target of bit copy must be trivially constructible.");
  To to;
  if constexpr (std::is_pointer_v<From>) {
    std::memcpy(&to, from, sizeof(To));
  } else {
    std::memcpy(&to, &from, sizeof(To));
  }
  return to;
}

template <typename To, typename FromRepr>
To
bit_copy(std::span<const FromRepr> from)
{
  static_assert(std::is_trivial_v<To>, "Target of bit copy must be trivially constructible.");
  ASSERT(from.size_bytes() >= sizeof(To), "Span must contain {} bytes but only contained {}", sizeof(To),
         from.size_bytes());
  To to;
  std::memcpy(&to, from.data(), sizeof(To));
  return to;
}

enum class Modifier : i8
{
  Const = -2,
  Volatile = -1,
  None = 0,
  Pointer = 1,
  Reference = 2,
  RValueReference = 3,
  Array = 4,
  Atomic = 5,
  Immutable,
  Packed,
  Restrict,
  Shared,
};

static constexpr std::string_view
ModifierToString(Modifier mod)
{
  switch (mod) {
  case Modifier::Const:
    return "const";
  case Modifier::Volatile:
    return "volatile";
  case Modifier::None:
    return "";
  case Modifier::Pointer:
    return "*";
  case Modifier::Reference:
    return "&";
  case Modifier::RValueReference:
    return "&&";
  case Modifier::Array:
    return "[";
  // these needs updating. it's not how they are supposed to look. This is language dependent too.
  case Modifier::Atomic:
    return "atomic";
  case Modifier::Immutable:
    return "immutable";
  case Modifier::Packed:
    return "packed";
  case Modifier::Restrict:
    return "restrict";
  case Modifier::Shared:
    return "shared";
  }
}

// This is meant to be the interface via which we interpret a range of bytes
class Type
{
  static constexpr auto ModifierNameStrSize = "const"sv.size() + "volatile"sv.size() + " *"sv.size();
  friend sym::dw::TypeSymbolicationContext;
  friend fmt::formatter<sym::Type>;

public:
  Immutable<std::string_view> name;
  Immutable<dw::IndexedDieReference> cu_die_ref;
  Immutable<Modifier> modifier;
  Immutable<u32> size_of;

private:
  friend class TypeSymbolicationContext;
  Type *type_chain;
  std::vector<Field> fields;

  // A disengaged optional, means this type does *not* represent one of the primitives (what DWARF calls "base
  // types").
  std::optional<BaseTypeEncoding> base_type;
  u32 array_bounds{0};
  bool is_typedef;
  // Flags used when constructing and "realizing" a type from the debug info data.
  bool resolved;
  bool processing;

public:
  // Qualified, i.e. some variant of cvref-types or type defs
  Type(dw::IndexedDieReference die_ref, u32 size_of, Type *target, bool is_typedef) noexcept;

  // "Normal" type constructor
  Type(dw::IndexedDieReference die_ref, u32 size_of, std::string_view name) noexcept;

  // "Special" types. Like void, Unit. Types with no size - and most importantly, no DW_AT_type attr in the DIE.
  Type(std::string_view name) noexcept;
  Type(Type &&o) noexcept;

  void add_field(std::string_view name, u64 offset_of, dw::DieReference ref) noexcept;
  void set_base_type_encoding(BaseTypeEncoding enc) noexcept;
  bool set_processing() noexcept;
  NonNullPtr<const Type> target_type() const noexcept;
  // Walks the `type_chain` and if _any_ of the types in between this type element and the base target type is a
  // reference, so is this. this is because we can have something like const Foo&, which is 3 `Type`s, (const+, &+,
  // Foo). We do different than gdb though. We say all references are the same thing: an address value
  bool is_reference() const noexcept;
  bool is_resolved() const noexcept;
  bool is_primitive() const noexcept;
  bool is_char_type() const noexcept;
  bool is_array_type() const noexcept;

  u32 size() noexcept;
  u32 size_bytes() noexcept;

  u32 members_count() const noexcept;
  const std::vector<Field> &member_variables() const noexcept;

  Type *get_layout_type() noexcept;
  // Todo: refactor this so we don't have to set it manually. It's ugly. It's easy to make it error prone.
  void set_array_bounds(u32 bounds) noexcept;

  /** Walks the type chain for this type, looking for a base type encoding (if it's a primitive of some sort). */
  constexpr std::optional<BaseTypeEncoding>
  get_base_type() const noexcept
  {
    auto it = this;
    while (it != nullptr) {
      if (it->base_type) {
        return it->base_type;
      }
      it = it->type_chain;
    }
    return std::nullopt;
  }

  constexpr u32
  array_size() const noexcept
  {
    return array_bounds;
  }
};

Modifier to_type_modifier_will_panic(DwarfTag tag) noexcept;
// A type that is reference like, is a type with inherent indirection. Pointers, references, r-value references,
// ranges, arrays.
bool is_reference_like(Modifier modifier) noexcept;
bool is_reference_like(const dw::DieMetaData *die) noexcept;

struct Symbol
{
  NonNullPtr<Type> type;
  Immutable<SymbolLocation> location;
  Immutable<std::string_view> name;
};

struct SymbolBlock
{
  AddrPtr entry_pc;
  AddrPtr end_pc;
  std::vector<Symbol> symbols;
};

struct BlockSymbolIterator
{

  static BlockSymbolIterator
  Begin(const std::vector<SymbolBlock> &blocks) noexcept
  {
    return BlockSymbolIterator{.blocks_data = blocks.data(),
                               .block_count = static_cast<u32>(blocks.size()),
                               .current_block_index = 0,
                               .symbol_index = 0};
  }

  static BlockSymbolIterator
  End(const std::vector<SymbolBlock> &blocks) noexcept
  {
    return BlockSymbolIterator{.blocks_data = blocks.data(),
                               .block_count = static_cast<u32>(blocks.size()),
                               .current_block_index = static_cast<u32>(blocks.size()),
                               .symbol_index = 0};
  }

  static BlockSymbolIterator
  Begin(const SymbolBlock *blocks, u32 count) noexcept
  {
    return BlockSymbolIterator{
      .blocks_data = blocks, .block_count = count, .current_block_index = 0, .symbol_index = 0};
  }

  static BlockSymbolIterator
  End(const SymbolBlock *blocks, u32 count) noexcept
  {
    if (count == 1 && blocks[0].symbols.empty()) {
      return BlockSymbolIterator{
        .blocks_data = blocks, .block_count = count, .current_block_index = 0, .symbol_index = 0};
    } else {
      return BlockSymbolIterator{
        .blocks_data = blocks, .block_count = count, .current_block_index = count, .symbol_index = 0};
    }
  }

  friend bool
  operator==(const BlockSymbolIterator &l, const BlockSymbolIterator &r) noexcept
  {
    ASSERT(l.blocks_data == r.blocks_data && l.block_count == r.block_count,
           "Expected iterators to be built from the same underlying data. If not, you're a moron.");
    return l.current_block_index == r.current_block_index && l.symbol_index == r.symbol_index;
  }

  BlockSymbolIterator &
  operator++() noexcept
  {
    advance();
    return *this;
  }

  BlockSymbolIterator
  operator++(int) noexcept
  {
    auto copy = *this;
    advance();
    return copy;
  }

  const Symbol *
  operator->() noexcept
  {
    return &blocks_data[current_block_index].symbols[symbol_index];
  }

  const Symbol *
  operator->() const noexcept
  {
    return &blocks_data[current_block_index].symbols[symbol_index];
  }

  const Symbol &
  operator*() noexcept
  {
    return blocks_data[current_block_index].symbols[symbol_index];
  }

  const Symbol &
  operator*() const noexcept
  {
    return blocks_data[current_block_index].symbols[symbol_index];
  }

  void
  advance() noexcept
  {
    ++symbol_index;
    if (symbol_index == blocks_data[current_block_index].symbols.size()) {
      ++current_block_index;
      symbol_index = 0;
    }
  }
  const SymbolBlock *blocks_data;
  u32 block_count;
  u32 current_block_index;
  u32 symbol_index;
};

} // namespace sym

namespace fmt {
template <> struct formatter<sym::Type>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::Type &type, FormatContext &ctx) const
  {
    std::array<const sym::Type *, 10> types{};
    i8 idx = 0;
    auto it = type.type_chain;
    types[idx++] = &type;
    while (it != nullptr) {
      if (!it->is_typedef) {
        types[idx++] = it;
      }
      it = it->type_chain;
    }
    std::sort(types.begin(), types.begin() + idx, [](const auto ptra, const auto ptrb) noexcept {
      return std::to_underlying(*ptra->modifier) < std::to_underlying(*ptrb->modifier);
    });

    auto index = 0u;
    auto out = ctx.out();
    auto type_span = std::span{types.begin(), types.begin() + idx};
    for (const auto t : type_span) {
      if (t->modifier != sym::Modifier::None) {
        out = fmt::format_to(out, "{}", ModifierToString(t->modifier));
        if (t->modifier == sym::Modifier::Array) {
          out = fmt::format_to(out, "{}]", t->array_bounds);
        }
      } else {
        out = fmt::format_to(out, "{}", t->name);
      }
      if (++index != type_span.size()) {
        out = fmt::format_to(out, " ");
      }
    }
    return out;
  }
};
} // namespace fmt
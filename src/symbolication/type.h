#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include "fmt/core.h"
#include "symbolication/dwarf/die.h"
#include "task.h"
#include "utils/immutable.h"

struct DebugInfoEntry;
struct TraceeController;

namespace sym {
class Type;
class Frame;

using TypeMap = std::unordered_map<u64, Type>;
using NameTypeMap = std::unordered_map<std::string_view, u64>;
using Bytes = std::span<const u8>;
using MemoryContentBytes = std::vector<u8>;

namespace dw {
class TypeSymbolicationContext;
};

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
  sym::Type *emplace_type(Offset type_id, sym::dw::IndexedDieReference die_ref, u32 type_size,
                          std::string_view name) noexcept;

  std::mutex &get_mutex() noexcept;
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

// This is meant to be the interface via which we interpret a range of bytes
class Type
{
  static constexpr auto ModifierNameStrSize = "const"sv.size() + "volatile"sv.size() + " *"sv.size();
  friend sym::dw::TypeSymbolicationContext;

public:
  Immutable<std::string_view> name;
  Immutable<dw::IndexedDieReference> cu_die_ref;

  enum class Modifier : i8
  {
    Const = -2,
    Volatile = -1,
    None = 0,
    Pointer = 1,
    Reference = 2,
    RValueReference = 3,
    Atomic = 4,
    Immutable,
    Packed,
    Restrict,
    Shared,
  };

  // Qualified, i.e. some variant of cvref-types
  Type(dw::IndexedDieReference die_ref, u32 size_of, Type *target) noexcept;

  // "Normal" type constructor
  Type(dw::IndexedDieReference die_ref, u32 size_of, std::string_view name) noexcept;
  Type(Type &&o) noexcept;

  void add_field(std::string_view name, u64 offset_of, dw::DieReference ref) noexcept;
  void set_base_type_encoding(BaseTypeEncoding enc) noexcept;
  bool set_processing() noexcept;
  NonNullPtr<Type> target_type() noexcept;
  // Walks the `type_chain` and if _any_ of the types in between this type element and the base target type is a
  // reference, so is this. this is because we can have something like const Foo&, which is 3 `Type`s, (const+, &+,
  // Foo). We do different than gdb though. We say all references are the same thing: an address value
  bool is_reference() const noexcept;
  bool is_resolved() const noexcept;
  u32 size() const noexcept;
  bool is_primitive() const noexcept;
  const std::vector<Field> &member_variables() const noexcept;

  static std::string_view
  ModifierToString(Modifier mod)
  {
    switch (mod) {
    case Modifier::Const:
      return "const";
    case Modifier::Volatile:
      return "volatile";
    case Modifier::None:
      PANIC("None modifier does not make sense");
    case Modifier::Pointer:
      return "*";
    case Modifier::Reference:
      return "&";
    case Modifier::RValueReference:
      return "&&";
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

  template <typename Out>
  constexpr auto
  serialize_type_name(Out out)
  {
    std::array<Type *, 10> ordered{};
    i8 idx = 0;
    auto it = type_chain;
    ordered[idx++] = this;
    while (it != nullptr) {
      ordered[idx++] = it;
      it = it->type_chain;
    }
    std::sort(ordered.begin(), ordered.begin() + idx, [](sym::Type *ptra, sym::Type *ptrb) noexcept {
      return std::to_underlying(*ptra->modifier) < std::to_underlying(*ptrb->modifier);
    });

    auto o = out;
    auto i = 0;
    if (ordered[i]->modifier != Modifier::None) {
      o = fmt::format_to(o, "{}", ModifierToString(ordered[i]->modifier));
    } else {
      o = fmt::format_to(o, "{}", *ordered[i]->name);
    }
    ++i;

    for (; i < idx; ++i) {
      if (ordered[i]->modifier != Modifier::None) {
        o = fmt::format_to(o, " {}", ModifierToString(ordered[i]->modifier));
      } else {
        o = fmt::format_to(o, " {}", *ordered[i]->name);
      }
    }

    return o;
  }

  constexpr auto
  typename_to_str()
  {
    std::array<Type *, 10> ordered{};
    u8 idx = 0;
    auto it = type_chain;
    ordered[idx++] = this;
    while (it != nullptr) {
      ordered[idx++] = it;
      it = it->type_chain;
    }
    std::sort(ordered.begin(), ordered.begin() + idx, [](sym::Type *ptra, sym::Type *ptrb) noexcept {
      return std::to_underlying(*ptra->modifier) < std::to_underlying(*ptrb->modifier);
    });

    std::vector<char> name_str{};
    name_str.reserve(name->size() + ModifierNameStrSize);
    auto out_iter = std::back_inserter(name_str);
    std::span<Type *> span{ordered.begin(), ordered.begin() + idx};

    auto i = 0;
    if (ordered[i]->modifier != Modifier::None) {
      out_iter = fmt::format_to(out_iter, "{}", ModifierToString(ordered[i]->modifier));
    } else {
      out_iter = fmt::format_to(out_iter, "{}", *ordered[i]->name);
    }
    ++i;

    for (; i < idx; ++i) {
      if (ordered[i]->modifier != Modifier::None) {
        out_iter = fmt::format_to(out_iter, " {}", ModifierToString(ordered[i]->modifier));
      } else {
        out_iter = fmt::format_to(out_iter, " {}", *ordered[i]->name);
      }
    }
    return name_str;
  }

  Immutable<Modifier> modifier;
  Immutable<u32> size_of;

  constexpr std::optional<BaseTypeEncoding>
  get_base_type() const noexcept
  {
    return base_type;
  }

private:
  friend class TypeSymbolicationContext;
  Type *type_chain;
  std::vector<Field> fields;

  // A disengaged optional, means this type does *not* represent one of the primitives (what DWARF calls "base
  // types").
  std::optional<BaseTypeEncoding> base_type;

  // Flags used when constructing and "realizing" a type from the debug info data.
  bool resolved;
  bool processing;
};

static constexpr bool
is_ref(Type::Modifier mod)
{
  const auto i = std::to_underlying(mod);
  return i < 4 && i > 0;
}

static constexpr bool
is_c_or_v(Type::Modifier mod)
{
  const auto i = std::to_underlying(mod);
  return i < 0;
}

Type::Modifier to_type_modifier_will_panic(DwarfTag tag) noexcept;
bool is_reference_like(Type::Modifier modifier) noexcept;
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
    return BlockSymbolIterator{.blocks = blocks.data(),
                               .count = static_cast<u32>(blocks.size()),
                               .current_block = 0,
                               .current_symbol_in_block_index = 0};
  }

  static BlockSymbolIterator
  End(const std::vector<SymbolBlock> &blocks) noexcept
  {
    return BlockSymbolIterator{.blocks = blocks.data(),
                               .count = static_cast<u32>(blocks.size()),
                               .current_block = static_cast<u32>(blocks.size()),
                               .current_symbol_in_block_index = 0};
  }

  static BlockSymbolIterator
  Begin(const SymbolBlock *blocks, u32 count) noexcept
  {
    return BlockSymbolIterator{
        .blocks = blocks, .count = count, .current_block = 0, .current_symbol_in_block_index = 0};
  }

  static BlockSymbolIterator
  End(const SymbolBlock *blocks, u32 count) noexcept
  {
    return BlockSymbolIterator{
        .blocks = blocks, .count = count, .current_block = count, .current_symbol_in_block_index = 0};
  }

  friend bool
  operator==(const BlockSymbolIterator &l, const BlockSymbolIterator &r) noexcept
  {
    ASSERT(l.blocks == r.blocks && l.count == r.count,
           "Expected iterators to be built from the same underlying data. If not, you're a moron.");
    return l.current_block == r.current_block &&
           l.current_symbol_in_block_index == r.current_symbol_in_block_index;
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
    return &blocks[current_block].symbols[current_symbol_in_block_index];
  }

  const Symbol *
  operator->() const noexcept
  {
    return &blocks[current_block].symbols[current_symbol_in_block_index];
  }

  const Symbol &
  operator*() noexcept
  {
    return blocks[current_block].symbols[current_symbol_in_block_index];
  }

  const Symbol &
  operator*() const noexcept
  {
    return blocks[current_block].symbols[current_symbol_in_block_index];
  }

  void
  advance() noexcept
  {
    ++current_symbol_in_block_index;
    if (current_symbol_in_block_index == blocks[current_block].symbols.size()) {
      ++current_block;
      current_symbol_in_block_index = 0;
    }
  }
  const SymbolBlock *blocks;
  u32 count;
  u32 current_block;
  u32 current_symbol_in_block_index;
};

enum class ValueDisplayType
{
  Primitive,
  Structured,
};

struct ValueDescriptor
{
  enum class Kind
  {
    Symbol,
    Field,
    AbsoluteAddress
  } kind;
  union
  {
    Symbol *symbol;
    Field *field;
    Type *type;
  };

  ValueDescriptor(Symbol *symbol) noexcept : kind(Kind::Symbol), symbol(symbol) {}
  ValueDescriptor(Field *field) noexcept : kind(Kind::Field), field(field) {}
  ValueDescriptor(Type *type) noexcept : kind(Kind::AbsoluteAddress), type(type) {}
};

class MemoryContentsObject;

class Value
{
public:
  using ShrPtr = std::shared_ptr<Value>;
  // contructor for `Values` that represent a block symbol (so a frame argument, stack variable, static / global
  // variable)
  Value(std::string_view name, Symbol &kind, u32 mem_contents_offset,
        std::shared_ptr<MemoryContentsObject> value_object) noexcept;

  // constructor for `Value`s that represent a member variable (possibly of some other `Value`)
  Value(std::string_view member_name, Field &kind, u32 mem_contents_offset,
        std::shared_ptr<MemoryContentsObject> value_object) noexcept;

  Value(Type &type, u32 mem_contents_offset, std::shared_ptr<MemoryContentsObject> value_object) noexcept;

  AddrPtr address() const noexcept;
  Type *type() const noexcept;
  std::span<const u8> memory_view() const noexcept;
  SharedPtr<MemoryContentsObject> take_memory_reference() noexcept;
  Immutable<std::string_view> name;
  Immutable<u32> mem_contents_offset;

private:
  // This value is either a block symbol (e.g. a variable on the stack) or a member of some block symbol (a field)
  ValueDescriptor value_origin;
  // The actual backing storage for this value. For instance, we may want to create multiple values out of a single
  // range of bytes in the target which is the case for struct Foo { int a; int b; } foo_val; we may want a Value
  // for a and b. The `MemoryContentsObject` is the storage for foo_val
  SharedPtr<MemoryContentsObject> value_object;
};

class MemoryContentsObject
{
  Immutable<MemoryContentBytes> bytes;

public:
  Immutable<AddrPtr> start;
  Immutable<AddrPtr> end;
  MemoryContentsObject(AddrPtr start, AddrPtr end, MemoryContentBytes &&data) noexcept;

  std::span<const u8> view(u32 offset, u32 size) const noexcept;

  // constructs a Value, essentially the "master value"; which represents the full MemoryContentsObject
  // Then we can chop that up into more sub values, all referring back to this MemoryContentsObject

  // The idea is this: say you have
  // struct bar { const char* ptr; int len; };
  // struct foo { bar b; int a; };
  // foo f{..}
  // if we want to build a Value of f.b, the "master value" is foo { bar, int }, i.e all bytes that `f` conists of.
  // We then chop that and hand out sub values like f.b This is because reads from the target debuggee is slow as
  // shit in computer time - reading the entire chunk is faster than managing sub parts here and there. Just pull
  // in the whole damn thing while we are still in kernel land. Objects are *RARELY* large enough to justify
  // anythign else.
  static std::shared_ptr<Value> create_frame_variable(TraceeController &tc, NonNullPtr<TaskInfo> task,
                                                      NonNullPtr<sym::Frame> frame, Symbol &symbol) noexcept;
};

template <typename OutBuf>
constexpr auto
format_primitive_to(Type &type, const Bytes &span, OutBuf outbuffer) noexcept
{
  const auto size_of = type.size_of;
  // 0 represents structured types
  const auto base_sz = type.get_base_type().transform([&](auto) { return *size_of; }).value_or(0);
  if (span.size() < base_sz)
    PANIC("Wanted to write a base type but the memory view in bytes was not large enough");

  if (type.is_reference()) {
    std::uintptr_t ptr = bit_copy<std::uintptr_t>(span);
    auto type_name_serialized = type.serialize_type_name(outbuffer);
    return fmt::format_to(type_name_serialized, " (0x{:x})", ptr);
  }

  if (base_sz == 0) {
    return type.serialize_type_name(outbuffer);
  }

  // std::span span{data};
  switch (type.get_base_type().value()) {
  case BaseTypeEncoding::DW_ATE_address: {
    std::uintptr_t value = bit_copy<std::uintptr_t>(span);
    return fmt::format_to(outbuffer, "0x{}", value);
  }
  case BaseTypeEncoding::DW_ATE_boolean: {
    bool value = bit_copy<bool>(span);
    return fmt::format_to(outbuffer, "{}", value);
  }
  case BaseTypeEncoding::DW_ATE_float: {
    if (size_of == 4) {
      float value = bit_copy<float>(span);
      return fmt::format_to(outbuffer, "{}", value);
    } else if (size_of == 8) {
      double value = bit_copy<double>(span);
      return fmt::format_to(outbuffer, "{}", value);
    } else {
      PANIC("Expected byte size of a floating point to be 4 or 8");
    }
  }
  case BaseTypeEncoding::DW_ATE_signed_char:
  case BaseTypeEncoding::DW_ATE_signed:
    switch (size_of) {
    case 1: {
      signed char value = bit_copy<signed char>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 2: {
      signed short value = bit_copy<signed short>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 4: {
      int value = bit_copy<int>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 8: {
      signed long long value = bit_copy<signed long long>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_unsigned_char:
  case BaseTypeEncoding::DW_ATE_unsigned:
    switch (size_of) {
    case 1: {
      u8 value = bit_copy<unsigned char>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 2: {
      u16 value = bit_copy<unsigned short>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 4: {
      u32 value = bit_copy<u32>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    case 8: {
      u64 value = bit_copy<u64>(span);
      return fmt::format_to(outbuffer, "{}", value);
    }
    }
    break;
  case BaseTypeEncoding::DW_ATE_UTF: {
    u32 value = bit_copy<u32>(span);
    return fmt::format_to(outbuffer, "{}", value);
  } break;
  case BaseTypeEncoding::DW_ATE_ASCII:
  case BaseTypeEncoding::DW_ATE_edited:
  case BaseTypeEncoding::DW_ATE_signed_fixed:
  case BaseTypeEncoding::DW_ATE_unsigned_fixed:
  case BaseTypeEncoding::DW_ATE_decimal_float:
  case BaseTypeEncoding::DW_ATE_imaginary_float:
  case BaseTypeEncoding::DW_ATE_packed_decimal:
  case BaseTypeEncoding::DW_ATE_numeric_string:
  case BaseTypeEncoding::DW_ATE_complex_float:

  case BaseTypeEncoding::DW_ATE_UCS: {
    TODO_FMT("Currently not implemented base type encoding: {}", to_str(type.get_base_type().value()));
    break;
  }
  case BaseTypeEncoding::DW_ATE_lo_user:
  case BaseTypeEncoding::DW_ATE_hi_user:
    break;
  }
  PANIC("unknown base type encoding");
}

} // namespace sym

namespace fmt {

template <> struct formatter<sym::Value>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(const sym::Value &val, FormatContext &ctx)
  {
    return format_primitive_to(*(val.type()), val.memory_view(), ctx.out());
  }
};
} // namespace fmt
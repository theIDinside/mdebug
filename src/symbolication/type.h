/** LICENSE TEMPLATE */
#pragma once
#include "common.h"
#include "symbolication/block.h"
#include "symbolication/dwarf/die_ref.h"
#include "utils/immutable.h"
#include "utils/indexing.h"
#include "utils/macros.h"
#include "utils/util.h"
#include <mutex>

using namespace std::string_view_literals;

namespace mdb {
class TraceeController;
class ObjectFile;
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
  std::mutex mWriteMutex;
  std::unordered_map<u64, sym::Type *> mTypeStorage;

public:
  static std::unique_ptr<TypeStorage> Create() noexcept;
  ~TypeStorage() noexcept;

  /** Search for a type that has type_id with the section offset specified by die_ref (indirectly, one must
   * retrieve DieMetaData for it first). If the type exists that type is returned, if it is not, a new type is
   * prepared and then that is returned. In DWARF, unfortunately, there are types for const Foo, Foo*, Foo& etc,
   * and they all have an additional level of indirection, pointing to the "Foo" class type/struct type die.
   * This has multiple problems, first of all, when we run into a Foo*, we must make sure that Foo also exist
   * before we return Foo* here, because the target type will be defined by Foo. */
  sym::Type *GetOrCreateNewType(sym::dw::IndexedDieReference dieReference) noexcept;
  sym::Type *GetUnitType() noexcept;
  sym::Type *CreateNewType(DwarfTag tag, Offset typeDieOffset, sym::dw::IndexedDieReference dieReference,
                           u32 typeSize, std::string_view name) noexcept;
};

namespace sym {

enum class LocKind : u8
{
  DwarfExpression,
  UnreadLocationList,
  LocationList,
};

struct LocationListEntry
{
  AddrPtr mStart, mEnd;
  std::span<const u8> mDwarfExpression;
};

class LocationList
{
  std::vector<LocationListEntry> mLocationList;

public:
  LocationList(std::vector<LocationListEntry> &&entries) noexcept;
  std::span<const LocationListEntry> Get() noexcept;
};

class SymbolLocation
{
  friend class Symbol;

  LocKind mKind;
  union
  {
    std::span<const u8> uDwarfExpression;
    u32 uLocListOffset;
    LocationList *uLocationList;
  };

public:
  MOVE_ONLY(SymbolLocation);

  template <typename T> constexpr SymbolLocation(T &&t)
  {
    using mdb::IsSame;
    if constexpr (IsSame<std::span<const u8>, T>()) {
      mKind = LocKind::DwarfExpression;
      uDwarfExpression = t;
    } else if constexpr (IsSame<u32, T>()) {
      mKind = LocKind::UnreadLocationList;
      uLocListOffset = t;
    } else if constexpr (IsSame<LocationList *, T>()) {
      mKind = LocKind::LocationList;
      uLocationList = t;
    } else {
      static_assert(always_false<T>, "Unhandled type");
    }
  }

  SymbolLocation &
  operator=(SymbolLocation &&rhs) noexcept
  {
    if (this != &rhs) {
      std::memcpy(this, &rhs, sizeof(SymbolLocation));
    }
    if (rhs.mKind == LocKind::LocationList) {
      rhs.uLocationList = nullptr;
    }
    return *this;
  }

  SymbolLocation(SymbolLocation &&o) noexcept
  {
    std::memcpy(this, &o, sizeof(SymbolLocation));
    if (o.mKind == LocKind::LocationList) {
      o.uLocationList = nullptr;
    }
  }

  static constexpr auto
  UnreadLocationList(u32 value)
  {
    return SymbolLocation{value};
  }

  static auto
  CreateLocationList(std::vector<LocationListEntry> &&entries)
  {
    return SymbolLocation{new LocationList{std::move(entries)}};
  }

  static constexpr auto
  Expression(std::span<const u8> expr) noexcept
  {
    return SymbolLocation{expr};
  }

  constexpr ~SymbolLocation() noexcept
  {
    if (mKind == LocKind::LocationList && uLocationList) {
      delete uLocationList;
    }
  }

  LocKind
  GetKind() const noexcept
  {
    return mKind;
  }

  u32
  LocListOffset() const noexcept
  {
    return uLocListOffset;
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
BitCopyFrom(From from) -> To
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
BitCopy(std::span<const FromRepr> from)
{
  static_assert(std::is_trivial_v<To>, "Target of bit copy must be trivially constructible.");
  ASSERT(from.size_bytes() >= sizeof(To), "Span must contain {} bytes but only contained {}", sizeof(To),
         from.size_bytes());
  To to;
  std::memcpy(&to, from.data(), sizeof(To));
  return to;
}

// A modifier of `None` means the `Type` with that modifier can be considered the "Layout type" or "Type describing
// this." It's essentially the interesting type information, not just some combinatorial type info.
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
  NEVER("Unknown modifier");
}

union EnumeratorConstValue
{
  u64 u;
  i64 i;
};

struct EnumeratorValues
{
  bool is_signed{false};
  std::unique_ptr<EnumeratorConstValue[]> e_values{nullptr};
};

// This is meant to be the interface via which we interpret a range of bytes
class Type
{
  static constexpr auto ModifierNameStrSize = "const"sv.size() + "volatile"sv.size() + " *"sv.size();
  friend sym::dw::TypeSymbolicationContext;
  friend fmt::formatter<sym::Type>;

public:
  Immutable<std::string_view> mName;
  Immutable<dw::IndexedDieReference> mCompUnitDieReference;
  Immutable<Modifier> mModifier;
  Immutable<bool> mIsTypedef;
  Immutable<u32> size_of;

private:
  // Flags used when constructing and "realizing" a type from the debug info data.
  bool mIsResolved;
  bool mIsProcessing;

  friend class TypeSymbolicationContext;
  Type *mTypeChain;
  std::vector<Field> mFields;

  // A disengaged optional, means this type does *not* represent one of the primitives (what DWARF calls "base
  // types").
  std::optional<BaseTypeEncoding> mBaseTypes;
  u32 mArrayBounds{0};
  EnumeratorValues mEnumValues{};
  DwarfTag mDebugInfoEntryTag;

public:
  // Qualified, i.e. some variant of cvref-types or type defs
  Type(DwarfTag debugInfoEntryTag, dw::IndexedDieReference debugInfoEntryReference, u32 sizeOf, Type *target,
       bool isTypedef) noexcept;

  // "Normal" type constructor
  Type(DwarfTag debugInfoEntryTag, dw::IndexedDieReference debugInfoEntryReference, u32 sizeOf,
       std::string_view name) noexcept;

  // "Special" types. Like void, Unit. Types with no size - and most importantly, no DW_AT_type attr in the DIE.
  Type(std::string_view name, size_t size = 0) noexcept;
  Type(Type &&o) noexcept;

  // Resolves the alias that this type def/using decl actually is, if it is one. If it's a concrete type, return
  // itself.
  Type *ResolveAlias() noexcept;
  void AddField(std::string_view name, u64 offsetOf, dw::DieReference debugInfoEntryReference) noexcept;
  void SetBaseTypeEncoding(BaseTypeEncoding enc) noexcept;
  bool SetProcessing() noexcept;
  NonNullPtr<Type> GetTargetType() noexcept;
  // Walks the `type_chain` and if _any_ of the types in between this type element and the base target type is a
  // reference, so is this. this is because we can have something like const Foo&, which is 3 `Type`s, (const+, &+,
  // Foo). We do different than gdb though. We say all references are the same thing: an address value
  bool IsReference() const noexcept;
  bool IsResolved() const noexcept;
  bool IsPrimitive() const noexcept;
  bool IsCharType() const noexcept;
  bool IsArrayType() const noexcept;

  DwarfTag
  GetDwarfTag() const noexcept
  {
    return mDebugInfoEntryTag;
  }

  const EnumeratorValues &
  GetEnumerations() const noexcept
  {
    return mEnumValues;
  }

  u32 Size() noexcept;
  u32 SizeBytes() noexcept;

  u32 MembersCount() noexcept;
  const std::vector<Field> &MemberFields() noexcept;

  Type *TypeDescribingLayoutOfThis() noexcept;
  // Todo: refactor this so we don't have to set it manually. It's ugly. It's easy to make it error prone.
  void SetArrayBounds(u32 bounds) noexcept;

  /** Walks the type chain for this type, looking for a base type encoding (if it's a primitive of some sort). */
  constexpr std::optional<BaseTypeEncoding>
  GetBaseType() const noexcept
  {
    auto it = this;
    while (it != nullptr) {
      if (it->mBaseTypes) {
        return it->mBaseTypes;
      }
      it = it->mTypeChain;
    }
    return std::nullopt;
  }

  constexpr u32
  ArraySize() const noexcept
  {
    return mArrayBounds;
  }
};

Modifier ToTypeModifierWillPanic(DwarfTag tag) noexcept;
// A type that is reference like, is a type with inherent indirection. Pointers, references, r-value references,
// ranges, arrays.
bool IsReferenceLike(Modifier modifier) noexcept;
bool IsReferenceLike(const dw::DieMetaData *die) noexcept;

struct Symbol
{
  NonNullPtr<Type> mType;
  Immutable<SymbolLocation> mLocation;
  Immutable<std::string_view> mName;
  std::span<const u8> GetDwarfExpression(AddrPtr programCounter) noexcept;
  bool Computed() noexcept;
};

struct SymbolBlock
{
  AddressRange mProgramCounterRange;
  std::vector<Symbol> mSymbols;
};

struct BlockSymbolIterator
{

  static BlockSymbolIterator
  Begin(const std::vector<SymbolBlock> &blocks) noexcept
  {
    return BlockSymbolIterator{.blocks_data = blocks.data(),
                               .mBlockCount = static_cast<u32>(blocks.size()),
                               .mCurrentBlockIndex = 0,
                               .mSymbolIndex = 0};
  }

  static BlockSymbolIterator
  End(const std::vector<SymbolBlock> &blocks) noexcept
  {
    return BlockSymbolIterator{.blocks_data = blocks.data(),
                               .mBlockCount = static_cast<u32>(blocks.size()),
                               .mCurrentBlockIndex = static_cast<u32>(blocks.size()),
                               .mSymbolIndex = 0};
  }

  static BlockSymbolIterator
  Begin(const SymbolBlock *blocks, u32 count) noexcept
  {
    return BlockSymbolIterator{
      .blocks_data = blocks, .mBlockCount = count, .mCurrentBlockIndex = 0, .mSymbolIndex = 0};
  }

  static BlockSymbolIterator
  End(const SymbolBlock *blocks, u32 count) noexcept
  {
    if (count == 1 && blocks[0].mSymbols.empty()) {
      return BlockSymbolIterator{
        .blocks_data = blocks, .mBlockCount = count, .mCurrentBlockIndex = 0, .mSymbolIndex = 0};
    } else {
      return BlockSymbolIterator{
        .blocks_data = blocks, .mBlockCount = count, .mCurrentBlockIndex = count, .mSymbolIndex = 0};
    }
  }

  friend bool
  operator==(const BlockSymbolIterator &l, const BlockSymbolIterator &r) noexcept
  {
    ASSERT(l.blocks_data == r.blocks_data && l.mBlockCount == r.mBlockCount,
           "Expected iterators to be built from the same underlying data. If not, you're a moron.");
    return l.mCurrentBlockIndex == r.mCurrentBlockIndex && l.mSymbolIndex == r.mSymbolIndex;
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
    return &blocks_data[mCurrentBlockIndex].mSymbols[mSymbolIndex];
  }

  const Symbol *
  operator->() const noexcept
  {
    return &blocks_data[mCurrentBlockIndex].mSymbols[mSymbolIndex];
  }

  const Symbol &
  operator*() noexcept
  {
    return blocks_data[mCurrentBlockIndex].mSymbols[mSymbolIndex];
  }

  const Symbol &
  operator*() const noexcept
  {
    return blocks_data[mCurrentBlockIndex].mSymbols[mSymbolIndex];
  }

  void
  advance() noexcept
  {
    ++mSymbolIndex;
    if (mSymbolIndex == blocks_data[mCurrentBlockIndex].mSymbols.size()) {
      ++mCurrentBlockIndex;
      mSymbolIndex = 0;
    }
  }
  const SymbolBlock *blocks_data;
  u32 mBlockCount;
  u32 mCurrentBlockIndex;
  u32 mSymbolIndex;
};

} // namespace sym
} // namespace mdb
namespace fmt {
namespace sym = mdb::sym;
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
    auto it = type.mTypeChain;
    types[idx++] = &type;
    while (it != nullptr) {
      if (!it->mIsTypedef) {
        types[idx++] = it;
      }
      it = it->mTypeChain;
    }
    std::sort(types.begin(), types.begin() + idx, [](const auto ptra, const auto ptrb) noexcept {
      return std::to_underlying(*ptra->mModifier) < std::to_underlying(*ptrb->mModifier);
    });

    auto index = 0u;
    auto out = ctx.out();
    auto type_span = std::span{types.begin(), types.begin() + idx};
    for (const auto t : type_span) {
      if (t->mModifier != sym::Modifier::None) {
        out = fmt::format_to(out, "{}", ModifierToString(t->mModifier));
        if (t->mModifier == sym::Modifier::Array) {
          out = fmt::format_to(out, "{}]", t->mArrayBounds);
        }
      } else {
        out = fmt::format_to(out, "{}", t->mName.Cast());
      }
      if (++index != type_span.size()) {
        out = fmt::format_to(out, " ");
      }
    }
    return out;
  }
};
} // namespace fmt
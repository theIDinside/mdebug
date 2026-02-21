/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <symbolication/type.h>
#include <symbolication/variable_reference.h>
#include <tracee_pointer.h>
#include <utils/byte_buffer.h>
#include <utils/immutable.h>
#include <utils/smartptr.h>

// std
#include <expected>
#include <memory_resource>
#include <span>

namespace mdb {
using Bytes = std::span<const u8>;
using MemoryContentBytes = mdb::ByteBuffer::OwnPtr;

namespace tc {
class SupervisorState;
}

class TaskInfo;
} // namespace mdb

namespace mdb::sym {

struct Field;
struct Symbol;
class Type;
class DebugAdapterSerializer;
class Frame;

enum class ValueDisplayType : u8
{
  Primitive,
  Structured,
};

class MemoryContentsObject;
class LazyMemoryContentsObject;

enum class ValueErrorType : u8
{
  InvalidSize,
  NotAReference,
  InvalidMemoryAddress,
  NoVariableContext
};

struct ValueError
{
  ValueErrorType mType;
  AddrPtr mAddress;
  u32 mSize;
  // Fill in additional fields here if necessary. Try to keep them POD (stack data). Errors should not allocate.

  using Error = std::unexpected<ValueError>;

  constexpr static Error
  InvalidSize(u32 size = 0) noexcept
  {
    return std::unexpected(ValueError{ .mType = ValueErrorType::InvalidSize, .mAddress = nullptr, .mSize = size });
  }

  constexpr static Error
  NotAReference() noexcept
  {
    return std::unexpected(ValueError{ .mType = ValueErrorType::NotAReference, .mAddress = nullptr, .mSize = 0 });
  }

  constexpr static Error
  InvalidMemoryAddress(AddrPtr addr = nullptr) noexcept
  {
    return Error(ValueError{ .mType = ValueErrorType::NotAReference, .mAddress = addr, .mSize = 0 });
  }

  constexpr static Error
  NoVariableContext() noexcept
  {
    return Error(ValueError{ .mType = ValueErrorType::NotAReference, .mAddress = nullptr, .mSize = 0 });
  }
};

// Dynamic representation of T
struct SyntheticType
{
  Type *mLayoutType;
  u32 mCount;
};

using VarContext = std::shared_ptr<VariableContext>;

class Value
{
  REF_COUNTED_WITH_WEAKREF_SUPPORT(Value);
  friend struct std::formatter<sym::Value>;
  friend class IValueResolve;
  friend class ResolveReference;
  // contructor for `Values` that represent a block symbol (so a frame argument, stack variable, static / global
  // variable)

  Value(VarContext context,
    std::string_view name,
    Symbol &kind,
    u32 memContentsOffset,
    std::shared_ptr<MemoryContentsObject> &&valueObject,
    DebugAdapterSerializer *serializer = nullptr) noexcept;

  // constructor for `Value`s that represent a member variable (possibly of some other `Value`)
  Value(VarContext context,
    std::string_view memberName,
    Field &kind,
    u32 memContentsOffset,
    std::shared_ptr<MemoryContentsObject> valueObject,
    DebugAdapterSerializer *serializer = nullptr) noexcept;

  Value(VarContext context,
    Type &type,
    u32 memContentsOffset,
    std::shared_ptr<MemoryContentsObject> valueObject,
    DebugAdapterSerializer *serializer = nullptr) noexcept;

  Value(VarContext context,
    std::string &&name,
    Type &type,
    u32 memContentsOffset,
    std::shared_ptr<MemoryContentsObject> valueObject,
    DebugAdapterSerializer *serializer = nullptr) noexcept;

  Value(VarContext context,
    std::string name,
    SyntheticType type,
    u32 memContentsOffset,
    std::shared_ptr<MemoryContentsObject> valueObject) noexcept;

  template <typename... Args>
  static Value *
  CreateForRef(Args &&...args) noexcept
  {
    return new Value{ std::forward<Args>(args)... };
  }

  // Union constructors
  void SetKind(Symbol *symbol) noexcept;
  void SetKind(Field *field) noexcept;
  void SetKind(Type *type) noexcept;
  void SetKind(SyntheticType type) noexcept;
  bool ValueIsBitField() const noexcept;

public:
  ~Value() noexcept;

  void SetDapSerializer(DebugAdapterSerializer *serializer) noexcept;

  AddrPtr Address() const noexcept;
  Type *GetType() const noexcept;
  Type *EnsureTypeResolved() const noexcept;

  std::optional<BitField> BitField() const noexcept;

  bool
  IsSynthetic() const
  {
    return kind == ValueKind::Synthetic;
  }

  std::span<const u8> MemoryView() const noexcept;
  std::span<const u8> FullMemoryView() const noexcept;
  SharedPtr<MemoryContentsObject> TakeMemoryReference() noexcept;

  /**
   * Converts the value as a pointer into the remote. Works only for references. If you want the address of the
   * actual value, `Address` does that.
   */
  [[nodiscard]] std::expected<AddrPtr, ValueError> ToRemotePointer() const noexcept;

  // Dereference
  [[nodiscard]] std::expected<std::vector<Ref<Value>>, ValueError> Dereference(u32 count) const noexcept;
  [[nodiscard]] std::expected<u32, ValueError> Dereference(
    u32 count, const std::function<bool(Ref<Value> value)> &onEachValue) const noexcept;

  [[nodiscard]] bool HasVisualizer() const noexcept;
  DebugAdapterSerializer *GetSerializer() noexcept;

  [[nodiscard]] bool IsValidValue() const noexcept;
  bool HasMember(std::string_view memberName) const noexcept;
  Ref<Value> GetMember(std::string_view memberName) noexcept;
  size_t PushMemberValue(std::function<bool(Ref<Value> value)> &&onEachValue);
  [[nodiscard]] VariableReferenceId ReferenceId() const noexcept;
  [[nodiscard]] bool IsLive() const noexcept;
  void RegisterContext() noexcept;
  bool OverwriteValueBytes(std::span<const std::byte> newBytes) noexcept;

  [[nodiscard]] VarContext GetVariableContext() const;
  template <typename Primitive> bool WritePrimitive(Primitive value) noexcept;

  Immutable<std::string> mName;
  Immutable<u32> mMemoryContentsOffsets;

private:
  std::expected<std::shared_ptr<MemoryContentsObject>, ValueError> DereferenceMemoryContentsObject(
    tc::SupervisorState *supervisor, u32 count) const;

  // This value is either a block symbol (e.g. a variable on the stack) or a member of some block symbol (a field)
  enum class ValueKind : u8
  {
    Symbol,
    Field,
    AbsoluteAddress,
    Synthetic
  } kind;
  union
  {
    Symbol *uSymbol;
    Field *uField;
    Type *uType;
    SyntheticType uSynthetic;
  };
  // The actual backing storage for this value. For instance, we may want to create multiple values out of a single
  // range of bytes in the target which is the case for struct Foo { int a; int b; } foo_val; we may want a Value
  // for a and b. The `MemoryContentsObject` is the storage for foo_val

  // TODO: Eventually, these types (ValueResolver and MemoryContentsObjects) will also take a memory allocator
  //  pointer as a member
  //  this is so that we don't have copy (potential) raw bytes read from the tracee -> the local arena allocated
  //  std::pmr::string types for instance
  //  and instead have both the raw data read from the tracee as well as the UI results, managed by a local arena
  //  allocator. PMR galore!
  std::shared_ptr<MemoryContentsObject> mValueObject;
  DebugAdapterSerializer *mVisualizer{ nullptr };
  VarContext mContext;
};

enum class ReadResultInfo : u8
{
  Success,
  Partial,
  Failed,
};

class MemoryContentsObject
{
public:
  NO_COPY(MemoryContentsObject);

  struct ReadResult
  {
    ReadResultInfo info;
    std::optional<int> errno;
    MemoryContentBytes value;

    bool
    is_ok() const noexcept
    {
      return info == ReadResultInfo::Success && value != nullptr;
    }
  };
  Immutable<AddrPtr> start;
  Immutable<AddrPtr> end;

  MemoryContentsObject(AddrPtr start, AddrPtr end) noexcept;
  virtual ~MemoryContentsObject() noexcept = default;

  virtual bool Refresh(tc::SupervisorState &supervisor) noexcept = 0;
  virtual std::span<const u8> RawView() noexcept = 0;
  virtual std::span<const u8> View(u32 offset, u32 size) noexcept = 0;

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
  static Ref<Value> CreateFrameVariable(
    tc::SupervisorState &tc, const sym::Frame &frame, Symbol &symbol, bool lazy) noexcept;

  static Ref<Value> CreateSyntheticVariable(tc::SupervisorState &tc,
    TaskInfo *task,
    SymbolFile *symbolFile,
    AddrPtr address,
    SyntheticType type,
    bool lazy);

  static ReadResult ReadMemory(tc::SupervisorState &tc, AddrPtr address, u64 size_of) noexcept;
  static ReadResult ReadMemory(
    std::pmr::memory_resource *allocator, tc::SupervisorState &tc, AddrPtr address, u32 size_of) noexcept;
};

class EagerMemoryContentsObject final : public MemoryContentsObject
{
  MemoryContentBytes mContents;

public:
  EagerMemoryContentsObject(AddrPtr start, AddrPtr end, MemoryContentBytes &&data) noexcept;

  bool Refresh(tc::SupervisorState &supervisor) noexcept final;
  std::span<const u8> RawView() noexcept final;
  std::span<const u8> View(u32 offset, u32 size) noexcept final;
};

class LazyMemoryContentsObject final : public MemoryContentsObject
{
  tc::SupervisorState &mSupervisor;
  MemoryContentBytes mContents{ nullptr };
  void CacheMemory() noexcept;

public:
  LazyMemoryContentsObject(tc::SupervisorState &supervisor, AddrPtr start, AddrPtr end) noexcept;
  bool Refresh(tc::SupervisorState &supervisor) noexcept final;
  std::span<const u8> RawView() noexcept final;
  std::span<const u8> View(u32 offset, u32 size) noexcept final;
};
} // namespace mdb::sym
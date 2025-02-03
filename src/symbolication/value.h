/** LICENSE TEMPLATE */
#pragma once
#include "symbolication/variable_reference.h"
#include "tracee_pointer.h"
#include "utils/immutable.h"
#include "utils/smartptr.h"
#include <common.h>
#include <fmt/core.h>
#include <memory_resource>
#include <span>
#include <utils/byte_buffer.h>
#include <utils/expected.h>

namespace mdb {
using Bytes = std::span<const u8>;
using MemoryContentBytes = mdb::ByteBuffer::OwnPtr;

class TraceeController;
struct TaskInfo;
} // namespace mdb

namespace mdb::sym {

struct Field;
struct Symbol;
class Type;
class DebugAdapterSerializer;
class Frame;

enum class ValueDisplayType
{
  Primitive,
  Structured,
};

class MemoryContentsObject;
class LazyMemoryContentsObject;

enum class ValueError
{
  Success,
  InvalidSize,
  SegFault
};

class ValueResolver;
using VarContext = std::shared_ptr<VariableContext>;

class Value
{
  REF_COUNTED_WITH_WEAKREF_SUPPORT(Value);
  friend struct fmt::formatter<sym::Value>;
  friend class IValueResolve;
  friend class ResolveReference;
  // contructor for `Values` that represent a block symbol (so a frame argument, stack variable, static / global
  // variable)

  Value(VarContext context, std::string_view name, Symbol &kind, u32 memContentsOffset,
        std::shared_ptr<MemoryContentsObject> &&valueObject,
        DebugAdapterSerializer *serializer = nullptr) noexcept;

  // constructor for `Value`s that represent a member variable (possibly of some other `Value`)
  Value(VarContext context, std::string_view memberName, Field &kind, u32 memContentsOffset,
        std::shared_ptr<MemoryContentsObject> valueObject, DebugAdapterSerializer *serializer = nullptr) noexcept;

  Value(VarContext context, Type &type, u32 memContentsOffset, std::shared_ptr<MemoryContentsObject> valueObject,
        DebugAdapterSerializer *serializer = nullptr) noexcept;
  Value(VarContext context, std::string &&name, Type &type, u32 memContentsOffset,
        std::shared_ptr<MemoryContentsObject> valueObject, DebugAdapterSerializer *serializer = nullptr) noexcept;

  template <typename... Args>
  static Value *
  CreateForRef(Args &&...args) noexcept
  {
    return new Value{std::forward<Args>(args)...};
  }

  // Union constructors
  void SetKind(Symbol *symbol) noexcept;
  void SetKind(Field *field) noexcept;
  void SetKind(Type *type) noexcept;

public:
  ~Value() noexcept;

  void
  SetDapSerializer(DebugAdapterSerializer *serializer) noexcept
  {
    mVisualizer = serializer;
  }

  AddrPtr Address() const noexcept;
  Type *GetType() const noexcept;
  std::span<const u8> MemoryView() const noexcept;
  std::span<const u8> FullMemoryView() const noexcept;
  SharedPtr<MemoryContentsObject> TakeMemoryReference() noexcept;
  mdb::Expected<AddrPtr, ValueError> ToRemotePointer() noexcept;
  bool HasVisualizer() const noexcept;
  DebugAdapterSerializer *GetVisualizer() noexcept;
  bool IsValidValue() const noexcept;
  bool HasMember(std::string_view memberName) noexcept;
  Ref<Value> GetMember(std::string_view memberName) noexcept;
  VariableReferenceId ReferenceId() const noexcept;
  bool IsLive() const noexcept;
  void RegisterContext() noexcept;

  Immutable<std::string> mName;
  Immutable<u32> mMemoryContentsOffsets;

private:
  // This value is either a block symbol (e.g. a variable on the stack) or a member of some block symbol (a field)
  enum class ValueKind
  {
    Symbol,
    Field,
    AbsoluteAddress
  } kind;
  union
  {
    Symbol *uSymbol;
    Field *uField;
    Type *uType;
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
  DebugAdapterSerializer *mVisualizer{nullptr};
  VarContext mContext;
};

enum class ReadResultInfo
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

  virtual bool Refresh(TraceeController &supervisor) noexcept = 0;
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
  static Ref<Value> CreateFrameVariable(TraceeController &tc, const sym::Frame &frame, Symbol &symbol,
                                        bool lazy) noexcept;

  static ReadResult ReadMemory(TraceeController &tc, AddrPtr address, u32 size_of) noexcept;
  static ReadResult ReadMemory(std::pmr::memory_resource *allocator, TraceeController &tc, AddrPtr address,
                               u32 size_of) noexcept;
};

class EagerMemoryContentsObject final : public MemoryContentsObject
{
  MemoryContentBytes mContents;

public:
  EagerMemoryContentsObject(AddrPtr start, AddrPtr end, MemoryContentBytes &&data) noexcept;

  bool Refresh(TraceeController &supervisor) noexcept final;
  std::span<const u8> RawView() noexcept final;
  std::span<const u8> View(u32 offset, u32 size) noexcept final;
};

class LazyMemoryContentsObject final : public MemoryContentsObject
{
  TraceeController &mSupervisor;
  MemoryContentBytes mContents{nullptr};
  void CacheMemory() noexcept;

public:
  LazyMemoryContentsObject(TraceeController &supervisor, AddrPtr start, AddrPtr end) noexcept;
  bool Refresh(TraceeController &supervisor) noexcept final;
  std::span<const u8> RawView() noexcept final;
  std::span<const u8> View(u32 offset, u32 size) noexcept final;
};
} // namespace mdb::sym
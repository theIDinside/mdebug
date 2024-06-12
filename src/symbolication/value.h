#pragma once
#include "utils/immutable.h"
#include <common.h>
#include <fmt/core.h>
#include <span>
#include <utils/byte_buffer.h>
#include <utils/expected.h>

using Bytes = std::span<const u8>;
using MemoryContentBytes = utils::ByteBuffer::OwnPtr;

struct TraceeController;
struct TaskInfo;

namespace sym {

struct Field;
struct Symbol;
class Type;
class ValueVisualizer;
class Frame;

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
class LazyMemoryContentsObject;

enum class ValueError
{
  Success,
  InvalidSize,
  SegFault
};

class ValueResolver;

class Value
{
public:
  friend struct fmt::formatter<sym::Value>;
  using ShrPtr = std::shared_ptr<Value>;
  // contructor for `Values` that represent a block symbol (so a frame argument, stack variable, static / global
  // variable)
  Value(std::string_view name, Symbol &kind, u32 mem_contents_offset,
        std::shared_ptr<MemoryContentsObject> &&value_object) noexcept;

  // constructor for `Value`s that represent a member variable (possibly of some other `Value`)
  Value(std::string_view member_name, Field &kind, u32 mem_contents_offset,
        std::shared_ptr<MemoryContentsObject> value_object) noexcept;

  Value(Type &type, u32 mem_contents_offset, std::shared_ptr<MemoryContentsObject> value_object) noexcept;
  Value(std::string &&name, Type &type, u32 mem_contents_offset,
        std::shared_ptr<MemoryContentsObject> value_object) noexcept;

  ~Value() noexcept;

  template <typename Vis, typename... Args>
  static std::shared_ptr<Value>
  WithVisualizer(std::shared_ptr<Value> &&value, Args... args) noexcept
  {
    value->visualizer = std::make_unique<Vis>(value, args...);
    return value;
  }

  AddrPtr address() const noexcept;
  Type *type() const noexcept;
  std::span<const u8> memory_view() const noexcept;
  std::span<const u8> full_memory_view() const noexcept;
  SharedPtr<MemoryContentsObject> take_memory_reference() noexcept;
  utils::Expected<AddrPtr, ValueError> to_remote_pointer() noexcept;
  void set_resolver(std::unique_ptr<ValueResolver> &&vis) noexcept;
  ValueResolver *get_resolver() noexcept;
  bool has_visualizer() const noexcept;
  ValueVisualizer *get_visualizer() noexcept;
  bool valid_value() const noexcept;

  Immutable<std::string> name;
  Immutable<u32> mem_contents_offset;

private:
  // This value is either a block symbol (e.g. a variable on the stack) or a member of some block symbol (a field)
  ValueDescriptor value_origin;
  // The actual backing storage for this value. For instance, we may want to create multiple values out of a single
  // range of bytes in the target which is the case for struct Foo { int a; int b; } foo_val; we may want a Value
  // for a and b. The `MemoryContentsObject` is the storage for foo_val
  std::shared_ptr<MemoryContentsObject> value_object;
  std::unique_ptr<ValueResolver> resolver{nullptr};
  std::unique_ptr<ValueVisualizer> visualizer{nullptr};
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

  virtual std::span<const u8> raw_view() noexcept = 0;
  virtual std::span<const u8> view(u32 offset, u32 size) noexcept = 0;

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
                                                      NonNullPtr<sym::Frame> frame, Symbol &symbol,
                                                      bool lazy) noexcept;

  static ReadResult read_memory(TraceeController &tc, AddrPtr address, u32 size_of) noexcept;
};

class EagerMemoryContentsObject final : public MemoryContentsObject
{
  MemoryContentBytes bytes;

public:
  EagerMemoryContentsObject(AddrPtr start, AddrPtr end, MemoryContentBytes &&data) noexcept;

  std::span<const u8> raw_view() noexcept final;
  std::span<const u8> view(u32 offset, u32 size) noexcept final;
};

class LazyMemoryContentsObject final : public MemoryContentsObject
{
  TraceeController &supervisor;
  MemoryContentBytes bytes{nullptr};
  void cache_memory() noexcept;

public:
  LazyMemoryContentsObject(TraceeController &supervisor, AddrPtr start, AddrPtr end) noexcept;
  std::span<const u8> raw_view() noexcept final;
  std::span<const u8> view(u32 offset, u32 size) noexcept final;
};
} // namespace sym
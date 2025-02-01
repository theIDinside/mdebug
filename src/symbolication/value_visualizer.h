/** LICENSE TEMPLATE */
#pragma once
#include "tracee_pointer.h"
#include "utils/smartptr.h"
#include <memory>
#include <memory_resource>
#include <optional>
#include <typedefs.h>
#include <vector>

namespace mdb {
class TraceeController;
class SymbolFile;
} // namespace mdb
namespace mdb::sym {

class Type;
class Value;
class MemoryContentsObject;

using ValuePtr = std::weak_ptr<Value>;
using TypePtr = sym::Type *;
using Children = std::span<Ref<Value>>;
using ChildStorage = std::vector<Ref<Value>>;
using VariablesReference = int;

/// This type and all it's customized derived variants
/// define and describe how to build, or "resolve" additional
/// values from a given value.
class ValueResolver
{
protected:
  bool mIsCached{false};
  TypePtr mType;
  SymbolFile *mSymbolFile;
  ValuePtr mValuePointer;
  ChildStorage mChildren;

public:
  ValueResolver(SymbolFile *objectFile, ValuePtr val, TypePtr type) noexcept;
  virtual ~ValueResolver() noexcept = default;

  Children Resolve(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept;
  Value *GetValue() noexcept;

  virtual std::optional<Children> HasCached(std::optional<u32> start, std::optional<u32> count) noexcept;

private:
  virtual Children GetChildren(TraceeController &tc, std::optional<u32> start,
                               std::optional<u32> count) noexcept = 0;
};

struct ValueRange
{
  std::optional<u32> start;
  std::optional<u32> count;
};

class IValueResolve
{
public:
  virtual std::vector<Ref<Value>> Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile,
                                          ValueRange valueRange = {}) noexcept = 0;
};

class ResolveReference final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

class ResolveCString final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

class ResolveArray final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(Value &value, TraceeController &tc, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

// The `value` visualizer - it formats a `Value` so that it can be displayed in the `value` field of a Variable
// object in the serialized data.

// The visualizers all take a memory resource/allocator, because it's serialized data is guaranteed (it *MUST* be)
// to be short lived. You are not supposed to keep it around - and if you do, take a copy of it with the normal
// global allocator. Really is that simple.
class DebugAdapterSerializer
{
public:
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  virtual std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name,
                                                    int variablesReference,
                                                    std::pmr::memory_resource *allocator) noexcept = 0;
};

class PrimitiveVisualizer final : public DebugAdapterSerializer
{
  std::optional<std::pmr::string> FormatValue(const Value &value, std::pmr::memory_resource *allocator) noexcept;
  std::optional<std::pmr::string> FormatEnum(Type &t, std::span<const u8> span,
                                             std::pmr::memory_resource *allocator) noexcept;

public:
  std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name, int variablesReference,
                                            std::pmr::memory_resource *allocator) noexcept final;
};

class DefaultStructVisualizer final : public DebugAdapterSerializer
{
public:
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name, int variablesReference,
                                            std::pmr::memory_resource *allocator) noexcept final;
};

class InvalidValueVisualizer final : public DebugAdapterSerializer
{
public:
  std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name, int variablesReference,
                                            std::pmr::memory_resource *allocator) noexcept final;
};

class ArrayVisualizer final : public DebugAdapterSerializer
{
public:
  std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name, int variablesReference,
                                            std::pmr::memory_resource *allocator) noexcept final;
};

class CStringVisualizer final : public DebugAdapterSerializer
{
  std::optional<std::pmr::string> FormatValue(const Value &value, std::optional<u32> null_terminator,
                                              std::pmr::memory_resource *allocator) noexcept;

public:
  std::optional<std::pmr::string> Serialize(const Value &value, std::string_view name, int variablesReference,
                                            std::pmr::memory_resource *allocator) noexcept final;
};

} // namespace mdb::sym
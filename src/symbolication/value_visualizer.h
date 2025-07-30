/** LICENSE TEMPLATE */
#pragma once
#include "tracee_pointer.h"
#include "utils/smartptr.h"
#include <common/typedefs.h>
#include <memory>
#include <memory_resource>
#include <optional>
#include <vector>

namespace mdb {
struct VariableContext;
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

struct ValueRange
{
  std::optional<u32> start;
  std::optional<u32> count;
};

class IValueResolve
{
public:
  virtual std::vector<Ref<Value>> Resolve(const VariableContext &context, SymbolFile *symbolFile,
                                          ValueRange valueRange = {}) noexcept = 0;
};

class ResolveReference final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(const VariableContext &context, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

class ResolveCString final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(const VariableContext &context, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

class ResolveArray final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(const VariableContext &context, SymbolFile *symbolFile,
                                  ValueRange valueRange = {}) noexcept final;
};

class ResolveRange final : public IValueResolve
{
public:
  std::vector<Ref<Value>> Resolve(const VariableContext &context, SymbolFile *symbolFile,
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

struct SerializeOptions
{
  int mDepth{2};
  bool mNewLineAfterMember{false};
};

class JavascriptValueSerializer
{
  template <typename FmtIterator>
  static FmtIterator Serialize(Value *value, FmtIterator fmtIterator, const SerializeOptions &options,
                               int currentDepth) noexcept;

public:
  template <typename StringType>
  static bool Serialize(Value *value, StringType &outputBuffer, const SerializeOptions &options) noexcept;
};

} // namespace mdb::sym
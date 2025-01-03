#pragma once
#include "tracee_pointer.h"
#include <memory>
#include <memory_resource>
#include <optional>
#include <typedefs.h>
#include <vector>

class TraceeController;
class SymbolFile;

namespace sym {

class Type;
class Value;
class MemoryContentsObject;

using ValuePtr = std::weak_ptr<Value>;
using TypePtr = sym::Type *;
using Children = std::span<std::shared_ptr<Value>>;
using ChildStorage = std::vector<std::shared_ptr<Value>>;
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

class ReferenceResolver final : public ValueResolver
{
  std::shared_ptr<MemoryContentsObject> mIndirectValueObject{nullptr};

  Children GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept override;

public:
  ReferenceResolver(SymbolFile *objectFile, std::weak_ptr<sym::Value> val, TypePtr type) noexcept;
  ~ReferenceResolver() noexcept override = default;
};

class CStringResolver final : public ValueResolver
{
  std::optional<u32> mNullTerminatorPosition{};
  std::shared_ptr<MemoryContentsObject> mIndirectValueObject{nullptr};

public:
  CStringResolver(SymbolFile *objectFile, std::weak_ptr<sym::Value> val, TypePtr type) noexcept;
  ~CStringResolver() noexcept override = default;

private:
  Children GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept override;
};

class ArrayResolver final : public ValueResolver
{
  // The base address of the array (1st byte)
  AddrPtr mBaseAddress;
  u32 mElementCount;
  TypePtr mLayoutType;

  Children get_all(TraceeController &tc) noexcept;

public:
  ArrayResolver(SymbolFile *objectFile, TypePtr layoutType, u32 arraySize, AddrPtr remoteBaseAddress) noexcept;
  ~ArrayResolver() noexcept override = default;

  std::optional<Children> HasCached(std::optional<u32> start, std::optional<u32> count) noexcept final;

private:
  AddrPtr AddressOf(u32 index) noexcept;
  Children GetChildren(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept override;
};

// The `value` visualizer - it formats a `Value` so that it can be displayed in the `value` field of a Variable
// object in the serialized data.

// The visualizers all take a memory resource/allocator, because it's serialized data is guaranteed (it *MUST* be)
// to be short lived. You are not supposed to keep it around - and if you do, take a copy of it with the normal
// global allocator. Really is that simple.
class ValueVisualizer
{
protected:
  std::weak_ptr<Value> mDataProvider;

public:
  explicit ValueVisualizer(std::weak_ptr<Value> value) noexcept;
  virtual ~ValueVisualizer() noexcept = default;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  virtual std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept = 0;
  virtual std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept = 0;
};

class PrimitiveVisualizer final : public ValueVisualizer
{
public:
  ~PrimitiveVisualizer() noexcept override = default;

  explicit PrimitiveVisualizer(std::weak_ptr<Value> value) noexcept;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept final;
  std::optional<std::pmr::string> FormatEnum(Type &t, std::span<const u8> span, std::pmr::memory_resource* allocator) noexcept;
  std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept final;
};

class DefaultStructVisualizer final : public ValueVisualizer
{
public:
  ~DefaultStructVisualizer() noexcept override = default;

  explicit DefaultStructVisualizer(std::weak_ptr<Value> value) noexcept;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept final;
  std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept final;
};

class InvalidValueVisualizer final : public ValueVisualizer
{
public:
  explicit InvalidValueVisualizer(std::weak_ptr<Value> provider) noexcept;
  ~InvalidValueVisualizer() noexcept override = default;
  std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept override;
  std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept final;
};

class ArrayVisualizer final : public ValueVisualizer
{

public:
  ~ArrayVisualizer() noexcept override = default;
  explicit ArrayVisualizer(std::weak_ptr<Value> provider) noexcept;
  std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept override;
  std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept final;
};

class CStringVisualizer final : public ValueVisualizer
{
  std::optional<u32> null_terminator;

public:
  explicit CStringVisualizer(std::weak_ptr<Value> provider, std::optional<u32> nullTerminatorPosition) noexcept;
  ~CStringVisualizer() noexcept override = default;
  std::optional<std::pmr::string> FormatValue(std::pmr::memory_resource* allocator) noexcept final;
  std::optional<std::pmr::string> DapFormat(std::string_view name, int variablesReference, std::pmr::memory_resource* allocator) noexcept final;
};

} // namespace sym
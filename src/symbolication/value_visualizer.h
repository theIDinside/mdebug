#pragma once
#include "utils/immutable.h"
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

using u32 = std::uint32_t;

struct ObjectFile;
struct TraceeController;

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
  bool cached{false};
  TypePtr type;
  ObjectFile *obj;
  ValuePtr value_ptr;
  ChildStorage children;

public:
  ValueResolver(ObjectFile *object_file, ValuePtr val, TypePtr type) noexcept;
  virtual ~ValueResolver() noexcept = default;

  Children resolve(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept;
  Value *value() noexcept;

  virtual std::optional<Children> has_cached(std::optional<u32> start, std::optional<u32> count) noexcept;

private:
  virtual Children get_children(TraceeController &tc, std::optional<u32> start,
                                std::optional<u32> count) noexcept = 0;
};

class DefaultStructResolver final : public ValueResolver
{
  VariablesReference ref;

public:
  DefaultStructResolver(ObjectFile *object_file, ValuePtr value, TypePtr layout_type,
                        VariablesReference ref) noexcept;
  ~DefaultStructResolver() noexcept final = default;

private:
  Children get_children(TraceeController &tc, std::optional<u32> start, std::optional<u32> count) noexcept final;
};

class CStringResolver final : public ValueResolver
{
  std::optional<u32> null_terminator{};
  std::shared_ptr<MemoryContentsObject> indirect_value_object{nullptr};

public:
  CStringResolver(ObjectFile *object_file, std::weak_ptr<sym::Value> val, TypePtr type) noexcept;
  ~CStringResolver() noexcept override = default;

private:
  Children get_children(TraceeController &tc, std::optional<u32> start,
                        std::optional<u32> count) noexcept override;
};

class ArrayResolver final : public ValueResolver
{
  // The base address of the array (1st byte)
  AddrPtr base_addr;
  u32 element_count;
  TypePtr layout_type;

  Children get_all(TraceeController &tc) noexcept;

public:
  ArrayResolver(ObjectFile *object_file, TypePtr layout_type, u32 array_size, AddrPtr remote_base_addr) noexcept;
  ~ArrayResolver() noexcept override = default;

  std::optional<Children> has_cached(std::optional<u32> start, std::optional<u32> count) noexcept final;

private:
  AddrPtr address_of(u32 index) noexcept;
  Children get_children(TraceeController &tc, std::optional<u32> start,
                        std::optional<u32> count) noexcept override;
};

// The `value` visualizer - it formats a `Value` so that it can be displayed in the `value` field of a Variable
// object in the serialized data.
class ValueVisualizer
{
protected:
  std::weak_ptr<Value> data_provider;

public:
  explicit ValueVisualizer(std::weak_ptr<Value>) noexcept;
  virtual ~ValueVisualizer() noexcept = default;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  virtual std::optional<std::string> format_value() noexcept = 0;
  virtual std::optional<std::string> dap_format(std::string_view name, int variablesReference) noexcept = 0;
};

class PrimitiveVisualizer final : public ValueVisualizer
{
public:
  ~PrimitiveVisualizer() noexcept override = default;

  explicit PrimitiveVisualizer(std::weak_ptr<Value>) noexcept;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  std::optional<std::string> format_value() noexcept final;
  std::optional<std::string> dap_format(std::string_view name, int variablesReference) noexcept final;
};

class DefaultStructVisualizer final : public ValueVisualizer
{
public:
  ~DefaultStructVisualizer() noexcept override = default;

  explicit DefaultStructVisualizer(std::weak_ptr<Value>) noexcept;
  // TODO(simon): add optimization where we can format our value directly to an outbuf?
  std::optional<std::string> format_value() noexcept final;
  std::optional<std::string> dap_format(std::string_view name, int variablesReference) noexcept final;
};

class ArrayVisualizer final : public ValueVisualizer
{

public:
  ~ArrayVisualizer() noexcept override = default;
  explicit ArrayVisualizer(std::weak_ptr<Value> provider) noexcept;
  std::optional<std::string> format_value() noexcept override;
  std::optional<std::string> dap_format(std::string_view name, int variablesReference) noexcept final;
};

class CStringVisualizer final : public ValueVisualizer
{
  std::optional<u32> null_terminator;

public:
  explicit CStringVisualizer(std::weak_ptr<Value> provider, std::optional<u32> null_terminator) noexcept;
  ~CStringVisualizer() noexcept override = default;
  std::optional<std::string> format_value() noexcept final;
  std::optional<std::string> dap_format(std::string_view name, int variablesReference) noexcept final;
};

} // namespace sym
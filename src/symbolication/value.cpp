#include "value.h"
#include "symbolication/dwarf_expressions.h"
#include "type.h"
#include "value_visualizer.h"
#include <supervisor.h>

namespace sym {
Value::Value(std::string_view name, Symbol &kind, u32 mem_contents_offset,
             std::shared_ptr<MemoryContentsObject> &&value_object) noexcept
    : name(name), mem_contents_offset(mem_contents_offset), value_origin(&kind),
      value_object(std::move(value_object))
{
}

Value::Value(std::string_view member_name, Field &kind, u32 containing_structure_offset,
             std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name(member_name), mem_contents_offset(containing_structure_offset + kind.offset_of), value_origin(&kind),
      value_object(std::move(value_object))
{
}

Value::Value(Type &type, u32 mem_contents_offset, std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name("value"), mem_contents_offset(mem_contents_offset), value_origin(&type),
      value_object(std::move(value_object))
{
}

Value::Value(std::string &&name, Type &type, u32 mem_contents_offset,
             std::shared_ptr<MemoryContentsObject> value_object) noexcept
    : name(std::move(name)), mem_contents_offset(mem_contents_offset), value_origin(&type),
      value_object(std::move(value_object))
{
}

Value::~Value() noexcept { DBGLOG(core, "Destroying value {}", name); }

AddrPtr
Value::address() const noexcept
{
  const auto result = value_object->start + mem_contents_offset;
  return result;
}

Type *
Value::type() const noexcept
{
  switch (value_origin.kind) {
  case ValueDescriptor::Kind::Symbol:
    return value_origin.symbol->type;
  case ValueDescriptor::Kind::Field:
    return value_origin.field->type;
  case ValueDescriptor::Kind::AbsoluteAddress:
    return value_origin.type;
  default:
    PANIC("Unknown valueDescriptor kind");
  }
}

utils::Expected<AddrPtr, ValueError>
Value::to_remote_pointer() noexcept
{
  const auto bytes = memory_view();
  if (bytes.size_bytes() != 8) {
    return utils::unexpected(ValueError::InvalidSize);
  }
  std::uintptr_t ptr{};
  std::memcpy(&ptr, bytes.data(), 8);
  return AddrPtr{ptr};
}

void
Value::set_resolver(std::unique_ptr<ValueResolver> &&res) noexcept
{
  resolver = std::move(res);
}

ValueResolver *
Value::get_resolver() noexcept
{
  return resolver.get();
}
bool
Value::has_visualizer() const noexcept
{
  return visualizer != nullptr;
}

bool
Value::valid_value() const noexcept
{
  if (value_object == nullptr) {
    return false;
  }

  return !value_object->raw_view().empty();
}

ValueVisualizer *
Value::get_visualizer() noexcept
{
  return visualizer.get();
}

SharedPtr<MemoryContentsObject>
Value::take_memory_reference() noexcept
{
  return value_object;
}

std::span<const u8>
Value::memory_view() const noexcept
{
  return value_object->view(mem_contents_offset, this->type()->size());
}

std::span<const u8>
Value::full_memory_view() const noexcept
{
  return value_object->raw_view();
}

MemoryContentsObject::MemoryContentsObject(AddrPtr start, AddrPtr end) noexcept : start(start), end(end) {}

EagerMemoryContentsObject::EagerMemoryContentsObject(AddrPtr start, AddrPtr end,
                                                     MemoryContentBytes &&data) noexcept
    : MemoryContentsObject(start, end), bytes(std::move(data))
{
}

LazyMemoryContentsObject::LazyMemoryContentsObject(TraceeController &supervisor, AddrPtr start,
                                                   AddrPtr end) noexcept
    : MemoryContentsObject(start, end), supervisor(supervisor)
{
}

std::span<const u8>
EagerMemoryContentsObject::raw_view() noexcept
{
  return bytes->span();
}

std::span<const u8>
EagerMemoryContentsObject::view(u32 offset, u32 size) noexcept
{
  return bytes->span().subspan(offset, size);
}

void
LazyMemoryContentsObject::cache_memory() noexcept
{
  DBGLOG(core, "[lazy transfer]: {} .. {}", start, end);
  if (auto res = supervisor.safe_read(start, end->get() - start->get()); res.is_expected()) {
    bytes = std::move(res.take_value());
  } else {
    bytes = std::move(res.take_error().bytes);
  }
}

std::span<const u8>
LazyMemoryContentsObject::raw_view() noexcept
{
  if (bytes == nullptr) {
    cache_memory();
  }

  return bytes->span();
}

std::span<const u8>
LazyMemoryContentsObject::view(u32 offset, u32 size) noexcept
{
  if (bytes == nullptr) {
    cache_memory();
  }

  return bytes->span().subspan(offset, size);
}

/*static*/
MemoryContentsObject::ReadResult
MemoryContentsObject::read_memory(TraceeController &tc, AddrPtr address, u32 size_of) noexcept
{
  if (auto res = tc.safe_read(address, size_of); res.is_expected()) {
    return ReadResult{.info = ReadResultInfo::Success, .value = res.take_value()};
  } else {
    const auto read_bytes = size_of - res.error().unread_bytes;
    if (read_bytes != 0) {
      return ReadResult{.info = ReadResultInfo::Partial, .value = std::move(res.take_error().bytes)};
    } else {
      return ReadResult{.info = ReadResultInfo::Failed, .value = nullptr};
    }
  }
}

/*static*/
SharedPtr<Value>
MemoryContentsObject::create_frame_variable(TraceeController &tc, NonNullPtr<TaskInfo> task,
                                            NonNullPtr<sym::Frame> frame, Symbol &symbol, bool lazy) noexcept
{
  const auto requested_byte_size = symbol.type->size();

  switch (symbol.location->kind) {
  case LocKind::DwarfExpression: {
    auto *fnSymbol = frame->maybe_get_full_symbols();
    if (!fnSymbol) {
      DBGLOG(core, "could not find function symbol for frame. Required to construct live variables.");
      TODO("Add support for situations where we can't actually construct the value");
      return nullptr;
    }
    auto interp =
      ExprByteCodeInterpreter{frame->level(), tc, task, symbol.location->dwarf_expr, fnSymbol->GetFrameBaseDwarfExpression()};
    const auto address = interp.run();
    if (lazy) {
      auto memory_object = std::make_shared<LazyMemoryContentsObject>(tc, address, address + requested_byte_size);
      return std::make_shared<Value>(symbol.name, symbol, 0, std::move(memory_object));
    } else {
      auto res = tc.safe_read(address, requested_byte_size);
      if (!res.is_expected()) {
        PANIC("Expected read to succeed");
      }
      auto memory_object =
        std::make_shared<EagerMemoryContentsObject>(address, address + requested_byte_size, res.take_value());
      return std::make_shared<Value>(symbol.name, symbol, 0, std::move(memory_object));
    }
  }
  case LocKind::AbsoluteAddress:
    TODO("Is LocKind::AbsoluteAddress really going to be a thing? Absolute address is only really useful "
         "together "
         "with sym::Type, not Symbol.");
    break;
  case LocKind::OffsetOf:
    PANIC("creating a frame variable with LocKind == OffsetOf not allowed");
    break;
  }
  return nullptr;
}

} // namespace sym
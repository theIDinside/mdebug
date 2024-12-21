#include "value.h"
#include "common.h"
#include "symbolication/dwarf_expressions.h"
#include "type.h"
#include "value_visualizer.h"
#include <supervisor.h>

namespace sym {
Value::Value(std::string_view name, Symbol &kind, u32 memContentsOffset,
             std::shared_ptr<MemoryContentsObject> &&valueObject) noexcept
    : mName(name), mMemoryContentsOffsets(memContentsOffset), mValueOrigin(&kind),
      mValueObject(std::move(valueObject))
{
}

Value::Value(std::string_view memberName, Field &kind, u32 containingStructureOffset,
             std::shared_ptr<MemoryContentsObject> valueObject) noexcept
    : mName(memberName), mMemoryContentsOffsets(containingStructureOffset + kind.offset_of), mValueOrigin(&kind),
      mValueObject(std::move(valueObject))
{
}

Value::Value(Type &type, u32 memContentsOffset, std::shared_ptr<MemoryContentsObject> valueObject) noexcept
    : mName("value"), mMemoryContentsOffsets(memContentsOffset), mValueOrigin(&type),
      mValueObject(std::move(valueObject))
{
}

Value::Value(std::string &&name, Type &type, u32 memContentsOffset,
             std::shared_ptr<MemoryContentsObject> valueObject) noexcept
    : mName(std::move(name)), mMemoryContentsOffsets(memContentsOffset), mValueOrigin(&type),
      mValueObject(std::move(valueObject))
{
}

Value::~Value() noexcept { DBGLOG(dap, "Destroying value {}", mName); }

AddrPtr
Value::Address() const noexcept
{
  const auto result = mValueObject->start + mMemoryContentsOffsets;
  return result;
}

Type *
Value::GetType() const noexcept
{
  switch (mValueOrigin.kind) {
  case ValueDescriptor::Kind::Symbol:
    return mValueOrigin.symbol->mType;
  case ValueDescriptor::Kind::Field:
    return mValueOrigin.field->type;
  case ValueDescriptor::Kind::AbsoluteAddress:
    return mValueOrigin.type;
  default:
    PANIC("Unknown valueDescriptor kind");
  }
}

utils::Expected<AddrPtr, ValueError>
Value::ToRemotePointer() noexcept
{
  const auto bytes = MemoryView();
  if (bytes.size_bytes() != 8) {
    return utils::unexpected(ValueError::InvalidSize);
  }
  std::uintptr_t ptr{};
  std::memcpy(&ptr, bytes.data(), 8);
  return AddrPtr{ptr};
}

void
Value::SetResolver(std::unique_ptr<ValueResolver> &&res) noexcept
{
  mResolver = std::move(res);
}

ValueResolver *
Value::GetResolver() noexcept
{
  return mResolver.get();
}
bool
Value::HasVisualizer() const noexcept
{
  return mVisualizer != nullptr;
}

bool
Value::IsValidValue() const noexcept
{
  if (mValueObject == nullptr) {
    return false;
  }

  return !mValueObject->RawView().empty();
}

ValueVisualizer *
Value::GetVisualizer() noexcept
{
  return mVisualizer.get();
}

SharedPtr<MemoryContentsObject>
Value::TakeMemoryReference() noexcept
{
  return mValueObject;
}

std::span<const u8>
Value::MemoryView() const noexcept
{
  return mValueObject->View(mMemoryContentsOffsets, this->GetType()->Size());
}

std::span<const u8>
Value::FullMemoryView() const noexcept
{
  return mValueObject->RawView();
}

MemoryContentsObject::MemoryContentsObject(AddrPtr start, AddrPtr end) noexcept : start(start), end(end) {}

EagerMemoryContentsObject::EagerMemoryContentsObject(AddrPtr start, AddrPtr end,
                                                     MemoryContentBytes &&data) noexcept
    : MemoryContentsObject(start, end), mContents(std::move(data))
{
}

LazyMemoryContentsObject::LazyMemoryContentsObject(TraceeController &supervisor, AddrPtr start,
                                                   AddrPtr end) noexcept
    : MemoryContentsObject(start, end), mSupervisor(supervisor)
{
}

std::span<const u8>
EagerMemoryContentsObject::RawView() noexcept
{
  return mContents->span();
}

std::span<const u8>
EagerMemoryContentsObject::View(u32 offset, u32 size) noexcept
{
  return mContents->span().subspan(offset, size);
}

void
LazyMemoryContentsObject::CacheMemory() noexcept
{
  DBGLOG(dap, "[lazy transfer]: {} .. {}", start, end);
  if (auto res = mSupervisor.SafeRead(start, end->get() - start->get()); res.is_expected()) {
    mContents = std::move(res.take_value());
  } else {
    mContents = std::move(res.take_error().bytes);
  }
}

std::span<const u8>
LazyMemoryContentsObject::RawView() noexcept
{
  if (mContents == nullptr) {
    CacheMemory();
  }

  return mContents->span();
}

std::span<const u8>
LazyMemoryContentsObject::View(u32 offset, u32 size) noexcept
{
  if (mContents == nullptr) {
    CacheMemory();
  }

  return mContents->span().subspan(offset, size);
}

/*static*/
MemoryContentsObject::ReadResult
MemoryContentsObject::ReadMemory(TraceeController &tc, AddrPtr address, u32 size_of) noexcept
{
  if (auto res = tc.SafeRead(address, size_of); res.is_expected()) {
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
MemoryContentsObject::ReadResult
MemoryContentsObject::ReadMemory(std::pmr::memory_resource *allocator, TraceeController &tc, AddrPtr address,
                                 u32 size_of) noexcept
{
  TODO("implement MemoryContentsObject that uses custom allocation strategies.");
}

/*static*/
SharedPtr<Value>
MemoryContentsObject::CreateFrameVariable(TraceeController &tc, NonNullPtr<TaskInfo> task,
                                          NonNullPtr<sym::Frame> frame, Symbol &symbol, bool lazy) noexcept
{
  const auto requested_byte_size = symbol.mType->Size();

  switch (symbol.mLocation->kind) {
  case LocKind::DwarfExpression: {
    auto *fnSymbol = frame->MaybeGetFullSymbolInfo();
    if (!fnSymbol) {
      DBGLOG(dap, "could not find function symbol for frame. Required to construct live variables.");
      TODO("Add support for situations where we can't actually construct the value");
      return nullptr;
    }
    auto interp = ExprByteCodeInterpreter{frame->FrameLevel(), tc, task, symbol.mLocation->dwarf_expr,
                                          fnSymbol->GetFrameBaseDwarfExpression()};
    const auto address = interp.Run();
    if (lazy) {
      auto memory_object = std::make_shared<LazyMemoryContentsObject>(tc, address, address + requested_byte_size);
      return std::make_shared<Value>(symbol.mName, symbol, 0, std::move(memory_object));
    } else {
      auto res = tc.SafeRead(address, requested_byte_size);
      if (!res.is_expected()) {
        PANIC("Expected read to succeed");
      }
      DBGLOG(dap, "[eager read]: {}:+{}", address, requested_byte_size);
      auto memory_object =
        std::make_shared<EagerMemoryContentsObject>(address, address + requested_byte_size, res.take_value());
      return std::make_shared<Value>(symbol.mName, symbol, 0, std::move(memory_object));
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

/*static*/
Value *
MemoryContentsObject::CreateFrameVariable(std::pmr::memory_resource *allocator, TraceeController &tc,
                                          NonNullPtr<TaskInfo> task, NonNullPtr<sym::Frame> frame, Symbol &symbol,
                                          bool lazy) noexcept
{
  TODO_IGNORE_WARN("Unimplemented", allocator, tc, task, frame, symbol, lazy);
  return nullptr;
}
} // namespace sym
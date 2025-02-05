/** LICENSE TEMPLATE */
#include "value.h"
#include "common.h"
#include "interface/dap/types.h"
#include "lib/arena_allocator.h"
#include "symbolication/dwarf/typeread.h"
#include "symbolication/dwarf_expressions.h"
#include "type.h"
#include "value_visualizer.h"
#include <memory_resource>
#include <supervisor.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/objfile.h>
#include <type_traits>

namespace mdb::sym {

void
Value::SetKind(Symbol *symbol) noexcept
{
  kind = ValueKind::Symbol;
  uSymbol = symbol;
}

void
Value::SetKind(Field *field) noexcept
{
  kind = ValueKind::Field;
  uField = field;
}

void
Value::SetKind(Type *type) noexcept
{
  kind = ValueKind::AbsoluteAddress;
  uType = type;
}

Value::Value(VarContext context, std::string_view name, Symbol &kind, u32 memContentsOffset,
             std::shared_ptr<MemoryContentsObject> &&valueObject, DebugAdapterSerializer *serializer) noexcept
    : mName(name), mMemoryContentsOffsets(memContentsOffset), mValueObject(std::move(valueObject)),
      mVisualizer(serializer), mContext(std::move(context))
{
  SetKind(&kind);
}

Value::Value(VarContext context, std::string_view memberName, Field &kind, u32 containingStructureOffset,
             std::shared_ptr<MemoryContentsObject> valueObject, DebugAdapterSerializer *serializer) noexcept
    : mName(memberName), mMemoryContentsOffsets(containingStructureOffset + kind.offset_of),
      mValueObject(std::move(valueObject)), mVisualizer(serializer), mContext(std::move(context))
{
  SetKind(&kind);
}

Value::Value(VarContext context, Type &type, u32 memContentsOffset,
             std::shared_ptr<MemoryContentsObject> valueObject, DebugAdapterSerializer *serializer) noexcept
    : mName("value"), mMemoryContentsOffsets(memContentsOffset), mValueObject(std::move(valueObject)),
      mVisualizer(serializer), mContext(std::move(context))
{
  SetKind(&type);
}

Value::Value(VarContext context, std::string &&name, Type &type, u32 memContentsOffset,
             std::shared_ptr<MemoryContentsObject> valueObject, DebugAdapterSerializer *serializer) noexcept
    : mName(std::move(name)), mMemoryContentsOffsets(memContentsOffset), mValueObject(std::move(valueObject)),
      mVisualizer(serializer), mContext(std::move(context))
{
  SetKind(&type);
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
  switch (kind) {
  case ValueKind::Symbol:
    return uSymbol->mType;
  case ValueKind::Field:
    return uField->type;
  case ValueKind::AbsoluteAddress:
    return uType;
  default:
    PANIC("Unknown valueDescriptor kind");
  }
}

mdb::Expected<AddrPtr, ValueError>
Value::ToRemotePointer() noexcept
{
  const auto bytes = MemoryView();
  if (bytes.size_bytes() != 8) {
    return mdb::unexpected(ValueError::InvalidSize);
  }
  std::uintptr_t ptr{};
  std::memcpy(&ptr, bytes.data(), 8);
  return AddrPtr{ptr};
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

bool
Value::HasMember(std::string_view memberName) noexcept
{
  if (auto type = GetType(); !type->IsResolved()) {
    sym::dw::TypeSymbolicationContext ts_ctx{*type->mCompUnitDieReference->GetUnitData()->GetObjectFile(), *type};
    ts_ctx.ResolveType();
  }

  for (const auto &field : GetType()->MemberFields()) {
    if (field.name == memberName) {
      return true;
    }
  }
  return false;
}

Ref<Value>
Value::GetMember(std::string_view memberName) noexcept
{
  auto type = GetType();

  if (!type->IsResolved()) {
    sym::dw::TypeSymbolicationContext ts_ctx{*type->mCompUnitDieReference->GetUnitData()->GetObjectFile(), *type};
    ts_ctx.ResolveType();
  }

  if (!mContext) {
    return nullptr;
  }

  auto resolver = SymbolFile::GetStaticResolver(*this);

  for (auto &mem : type->MemberFields()) {
    if (mem.name == memberName) {
      ASSERT(mContext, "Creating member from value that has no context");
      auto variableContext = mem.type->IsPrimitive() ? VariableContext::CloneFrom(0, *mContext)
                                                     : Tracer::Get().CloneFromVariableContext(*mContext);
      const auto vId = variableContext->mId;
      auto memberValue = Ref<sym::Value>::MakeShared(variableContext, mem.name, const_cast<sym::Field &>(mem),
                                                     mMemoryContentsOffsets, TakeMemoryReference());
      ObjectFile::InitializeDataVisualizer(*memberValue);

      if (vId > 0) {
        variableContext->mTask->CacheValueObject(vId, memberValue);
      }
      return memberValue;
    }
  }
  return nullptr;
}

VariableReferenceId
Value::ReferenceId() const noexcept
{
  return mContext->mId;
}

bool
Value::IsLive() const noexcept
{
  return mContext->IsLiveReference();
}

void
Value::RegisterContext() noexcept
{
  Tracer::Get().SetVariableContext(mContext);
  mContext->mTask->CacheValueObject(mContext->mId, RcHandle<sym::Value>{this});
}

bool
Value::OverwriteValueBytes(u32 offset, const std::span<const std::byte> newBytes) noexcept
{
  auto oldSpan = MemoryView();
  if (newBytes.size() > oldSpan.size()) {
    return false;
  }
  auto addr = Address();

  auto supervisor = mContext->mTask->GetSupervisor();

  const auto result = supervisor->GetInterface().WriteBytes(addr, (const u8 *)newBytes.data(), newBytes.size());
  mValueObject->Refresh(*supervisor);

  return result.success;
}

template <class T>
static constexpr auto
ByteViewOf(const T &t) -> std::span<const std::byte>
{
  return std::as_bytes(std::span<const T>{std::addressof(t), 1});
}

template <typename Primitive>
bool
Value::WritePrimitive(Primitive value) noexcept
{
  auto type = GetType();

  if (type->IsReference()) {
    if constexpr (!std::is_integral_v<Primitive>) {
      return false;
    }
    auto cast = static_cast<u64>(value);
    return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
  }

  // if *not* a reference, or *is* array type, get layout describing type
  if (!(GetType()->IsReference() || GetType()->IsArrayType())) {
    type = type->TypeDescribingLayoutOfThis();
  }

  auto baseType = type->GetBaseType();
  // TODO(simon): implement support for enum, which can have base type underlying types (at which point baseType ==
  // nullopt). When that is fixed, the check below should be baseType->IsPrimitive(), which also lets enum types
  // (with primitive backing storage) through
  if (!baseType) {
    return false;
  }
  auto sz = type->SizeBytes();
  switch (baseType.value()) {
  case BaseTypeEncoding::DW_ATE_float: {
    if constexpr (!std::is_floating_point_v<Primitive>) {
      return false;
    }
    switch (sz) {
    case 4: {
      auto cast = static_cast<f32>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 8: {
      auto cast = static_cast<f64>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    }
  } break;
  case BaseTypeEncoding::DW_ATE_signed_char:
    [[fallthrough]];
  case BaseTypeEncoding::DW_ATE_signed: {
    if constexpr (!std::is_integral_v<Primitive>) {
      return false;
    }
    switch (sz) {
    case 1: {
      auto cast = static_cast<i8>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 2: {
      auto cast = static_cast<i16>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 4: {
      auto cast = static_cast<i32>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 8: {
      auto cast = static_cast<i64>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    }
  } break;
  case BaseTypeEncoding::DW_ATE_unsigned_char:
    [[fallthrough]];
  case BaseTypeEncoding::DW_ATE_unsigned: {
    if constexpr (!std::is_integral_v<Primitive>) {
      return false;
    }
    switch (sz) {
    case 1: {
      auto cast = static_cast<u8>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 2: {
      auto cast = static_cast<u16>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 4: {
      auto cast = static_cast<u32>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    case 8: {
      auto cast = static_cast<u64>(value);
      return OverwriteValueBytes(mMemoryContentsOffsets, ByteViewOf(cast));
    } break;
    }
  } break;

  default:
    break;
  }
  return false;
}

template bool Value::WritePrimitive<i8>(i8 value) noexcept;
template bool Value::WritePrimitive<i16>(i16 value) noexcept;
template bool Value::WritePrimitive<i32>(i32 value) noexcept;
template bool Value::WritePrimitive<i64>(i64 value) noexcept;

template bool Value::WritePrimitive<u8>(u8 value) noexcept;
template bool Value::WritePrimitive<u16>(u16 value) noexcept;
template bool Value::WritePrimitive<u32>(u32 value) noexcept;
template bool Value::WritePrimitive<u64>(u64 value) noexcept;

template bool Value::WritePrimitive<f32>(f32 value) noexcept;
template bool Value::WritePrimitive<f64>(f64 value) noexcept;

DebugAdapterSerializer *
Value::GetVisualizer() noexcept
{
  return mVisualizer;
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

bool
EagerMemoryContentsObject::Refresh(TraceeController &supervisor) noexcept
{
  auto mem = ReadMemory(supervisor, start, RawView().size_bytes());
  ASSERT(mem.is_ok(), "failed to refresh {} .. {}", start, end);
  mContents = std::move(mem.value);
  return mem.is_ok();
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

bool
LazyMemoryContentsObject::Refresh(TraceeController &supervisor) noexcept
{
  CacheMemory();
  return true;
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

static void
ReadInLocationList(Symbol &symbol, alloc::ArenaResource *allocator, const ElfSection &locList) noexcept
{
  uint64_t base;
  uint64_t start;
  uint64_t end;

  std::span<const u8> loclist = locList.GetDataAs<const u8>().subspan(symbol.mLocation->LocListOffset());

  struct span
  {
    const u8 *ptr;
    u64 size;

    constexpr void
    Move(u32 offset)
    {
      ptr += offset;
      size -= offset;
    }

    inline void
    CopyTo(uint64_t &value) noexcept
    {
      std::memcpy(&value, ptr, 8);
      Move(8);
    }

    inline void
    CopyTo(uint16_t &value) noexcept
    {
      std::memcpy(&value, ptr, 2);
      Move(2);
    }
  };

  span s{.ptr = loclist.data(), .size = loclist.size()};

  auto arena = allocator->ScopeAllocation();
  std::pmr::vector<LocationListEntry> parsed{arena.GetAllocator()};
  parsed.reserve(512);
  std::vector<LocationListEntry> result;

  while (s.size >= 16u) {
    s.CopyTo(start);
    if (start == 0xFFFFFFFF'FFFFFFFF) {
      s.CopyTo(base);
      continue;
    }
    s.CopyTo(end);
    if (start == 0 && end == 0) {
      break;
    }
    u16 dwarfExpressionLength;
    s.CopyTo(dwarfExpressionLength);
    parsed.push_back(LocationListEntry{
      .mStart = start + base, .mEnd = end + base, .mDwarfExpression = {s.ptr, dwarfExpressionLength}});
    s.Move(dwarfExpressionLength);
  }
  result.reserve(parsed.size());
  std::copy(std::begin(parsed), std::end(parsed), std::back_inserter(result));

  symbol.mLocation = SymbolLocation::CreateLocationList(std::move(result));
}

/*static*/
Ref<Value>
MemoryContentsObject::CreateFrameVariable(TraceeController &tc, const sym::Frame &frame, Symbol &symbol,
                                          bool lazy) noexcept
{
  const auto requested_byte_size = symbol.mType->Size();

  auto *fnSymbol = frame.MaybeGetFullSymbolInfo();
  if (!fnSymbol) {
    DBGLOG(dap, "could not find function symbol for frame. Required to construct live variables.");
    TODO("Add support for situations where we can't actually construct the value");
    return nullptr;
  }

  if (!symbol.Computed()) {
    ReadInLocationList(symbol, tc.GetDebugAdapterProtocolClient()->GetCommandArenaAllocator(),
                       *frame.GetSymbolFile()->GetObjectFile()->GetElf()->debug_loclist);
  }
  auto dwarfExpression = symbol.GetDwarfExpression(frame.GetSymbolFile()->UnrelocateAddress(frame.FramePc()));

  if (dwarfExpression.empty()) {
    return Ref<Value>::MakeShared(nullptr, symbol.mName, symbol, 0u, nullptr);
  }
  auto interp = ExprByteCodeInterpreter{frame.FrameLevel(), tc, *frame.mTask, dwarfExpression,
                                        fnSymbol->GetFrameBaseDwarfExpression()};

  auto variableContext =
    symbol.mType->IsPrimitive()
      ? VariableContext::FromFrame(0, ContextType::Variable, frame)
      : VariableContext::FromFrame(Tracer::Get().NewVariablesReference(), ContextType::Variable, frame);

  const auto address = interp.Run();

  if (lazy) {
    auto memory_object = std::make_shared<LazyMemoryContentsObject>(tc, address, address + requested_byte_size);
    return Ref<sym::Value>::MakeShared(std::move(variableContext), symbol.mName, symbol, 0u,
                                       std::move(memory_object));
  }

  auto res = tc.SafeRead(address, requested_byte_size);
  if (!res.is_expected()) {
    PANIC("Expected read to succeed");
  }
  DBGLOG(dap, "[eager read]: {}:+{}", address, requested_byte_size);
  auto memory_object =
    std::make_shared<EagerMemoryContentsObject>(address, address + requested_byte_size, res.take_value());
  return Ref<Value>::MakeShared(std::move(variableContext), symbol.mName, symbol, 0u, std::move(memory_object));
}

} // namespace mdb::sym
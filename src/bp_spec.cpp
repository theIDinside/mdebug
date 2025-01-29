/** LICENSE TEMPLATE */
#include "bp_spec.h"

namespace mdb {

BreakpointSpecification::BreakpointSpecification(DapBreakpointType kind, std::optional<std::string> condition,
                                                 std::optional<std::string> hitCondition) noexcept
    : mKind(kind), mCondition(std::move(condition)), mHitCondition(std::move(hitCondition)), uSource(nullptr)
{
}

void
BreakpointSpecification::DestroyUnion() noexcept
{
  if ((void *)uSource == nullptr) {
    return;
  }
  switch (mKind) {
  case DapBreakpointType::source:
    delete uSource;
    break;
  case DapBreakpointType::function:
    delete uFunction;
    break;
  case DapBreakpointType::instruction:
    delete uInstruction;
    break;
  }
  uSource = nullptr;
}

BreakpointSpecification::~BreakpointSpecification() noexcept { DestroyUnion(); }

BreakpointSpecification::BreakpointSpecification(std::optional<std::string> condition,
                                                 std::optional<std::string> hitCondition,
                                                 SourceBreakpointSpecPair *src) noexcept
    : mKind(DapBreakpointType::source), mCondition(std::move(condition)), mHitCondition(std::move(hitCondition)),
      uSource(src)
{
}

BreakpointSpecification::BreakpointSpecification(std::optional<std::string> condition,
                                                 std::optional<std::string> hitCondition,
                                                 FunctionBreakpointSpec *fun) noexcept
    : mKind(DapBreakpointType::function), mCondition(std::move(condition)), mHitCondition(std::move(hitCondition)),
      uFunction(fun)
{
}

BreakpointSpecification::BreakpointSpecification(std::optional<std::string> condition,
                                                 std::optional<std::string> hitCondition,
                                                 InstructionBreakpointSpec *ins) noexcept
    : mKind(DapBreakpointType::instruction), mCondition(std::move(condition)),
      mHitCondition(std::move(hitCondition)), uInstruction(ins)
{
}

BreakpointSpecification::BreakpointSpecification(BreakpointSpecification &&moveFrom) noexcept
    : mKind(moveFrom.mKind), mCondition(std::move(moveFrom.mCondition)),
      mHitCondition(std::move(moveFrom.mHitCondition)), uSource(nullptr)
{
  TakeVariant(this, &moveFrom);
}

BreakpointSpecification::BreakpointSpecification(const BreakpointSpecification &copy) noexcept
    : mKind(copy.mKind), mCondition(copy.mCondition), mHitCondition(copy.mHitCondition), uSource(nullptr)
{
  CloneVariant(this, &copy);
}

BreakpointSpecification &
BreakpointSpecification::operator=(const BreakpointSpecification &copy) noexcept
{
  if (this != &copy) {
    mKind = copy.mKind;
    mCondition = copy.mCondition;
    mHitCondition = copy.mHitCondition;
    DestroyUnion();
    CloneVariant(this, &copy);
  }
  return *this;
}

std::optional<u32>
BreakpointSpecification::Column() const noexcept
{
  switch (mKind) {
  case DapBreakpointType::source:
    return uSource ? uSource->mSpec.column : std::nullopt;
  case DapBreakpointType::function:
    [[fallthrough]];
  case DapBreakpointType::instruction:
    return {};
  }
}

std::optional<u32>
BreakpointSpecification::Line() const noexcept
{
  switch (mKind) {
  case DapBreakpointType::source:
    return uSource ? std::optional{uSource->mSpec.line} : std::nullopt;
  case DapBreakpointType::function:
    [[fallthrough]];
  case DapBreakpointType::instruction:
    return {};
  }
}

/* static */
void
BreakpointSpecification::TakeVariant(BreakpointSpecification *out, BreakpointSpecification *takeFrom) noexcept
{
  // Makes sure out's pointer is null, because this will get swapped with takeFrom's spec pointer
  out->DestroyUnion();
  switch (takeFrom->mKind) {
  case DapBreakpointType::source:
    return std::swap(out->uSource, takeFrom->uSource);
  case DapBreakpointType::function:
    return std::swap(out->uFunction, takeFrom->uFunction);
  case DapBreakpointType::instruction:
    return std::swap(out->uInstruction, takeFrom->uInstruction);
  }
}

// static
void
BreakpointSpecification::CloneVariant(BreakpointSpecification *out, const BreakpointSpecification *spec) noexcept
{
  switch (spec->mKind) {
  case DapBreakpointType::source: {
    out->uSource = new SourceBreakpointSpecPair{*spec->uSource};
    break;
  }
  case DapBreakpointType::function: {
    out->uFunction = new FunctionBreakpointSpec{*spec->uFunction};
    break;
  }
  case DapBreakpointType::instruction: {
    out->uInstruction = new InstructionBreakpointSpec{*spec->uInstruction};
    break;
  }
  default:
    PANIC("Unexpected type");
    break;
  }
}

// static
BreakpointSpecification *
BreakpointSpecification::Clone(const BreakpointSpecification *spec) noexcept
{
  if (!spec) {
    return nullptr;
  }
  auto res = new BreakpointSpecification{spec->mKind, spec->mCondition, spec->mHitCondition};
  CloneVariant(res, spec);
  return res;
}

std::unique_ptr<BreakpointSpecification>
BreakpointSpecification::Clone() const noexcept
{
  return std::unique_ptr<BreakpointSpecification>{Clone(this)};
}
}; // namespace mdb
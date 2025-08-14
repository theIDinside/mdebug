#pragma once
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf/typeread.h>
#include <symbolication/type.h>
#include <symbolication/value.h>
#include <symbolication/value_visualizer.h>

#include <format>

namespace mdb::sym {

template <typename Iterator, typename... Args> concept SerializeIter = (std::is_same_v<Iterator, Args> || ...);

template <typename Iterator>
concept IsSerializeIter = SerializeIter<Iterator, char *, std::back_insert_iterator<std::string>>;

template <IsSerializeIter Iterator>
Iterator
JsonSerializeValue(Value *value, Iterator outputIterator, const SerializeOptions &options) noexcept
{
  auto it = outputIterator;
  auto valueType = value->GetType();
  if (!valueType->IsResolved()) {
    sym::dw::TypeSymbolicationContext symbolicationContext{
      *valueType->mCompUnitDieReference->GetUnitData()->GetObjectFile(), *valueType
    };
    symbolicationContext.ResolveType();
  }

  if (value->GetType()->IsPrimitive()) {
    FormatValue(*value, it);
    return true;
  }

  if (options.mNewLineAfterMember) {
    it = std::format_to(it, "{{\n");
  } else {
    it = std::format_to(it, "{{ ");
  }

  for (const auto &m : value->GetType()->MemberFields()) {
    auto v = value->GetMember(m.mName);
    it = Serialize(v, it, options, options.mDepth - 1);
  }
  std::format_to(std::back_inserter(outputBuffer), "}}");

  return true;
}

} // namespace mdb::sym
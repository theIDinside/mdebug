#pragma once
#include "../common.h"
#include "dwarf/die.h"

namespace sym {

namespace dw {
// class UnitData;
// struct DieMetaData;
// struct DieReference;
// struct IndexedDieReference;
}; // namespace dw

struct FunctionSymbol
{
  AddrPtr start = nullptr;
  AddrPtr end = nullptr;
  std::string_view member_of{};
  std::string_view name{};
  // std::vector<dw::IndexedDieReference> maybe_origin_die;
  std::array<dw::IndexedDieReference, 3> maybe_origin_dies;

  std::string
  build_full_name() const
  {
    if (!member_of.empty())
      return fmt::format("{}::{}", member_of, name);
    else
      return std::string{name};
  }
};
} // namespace sym
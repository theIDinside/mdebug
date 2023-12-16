#include "fnsymbol.h"
namespace sym {

std::string
FunctionSymbol::build_full_name() const noexcept
{
  if (!member_of.empty())
    return fmt::format("{}::{}", member_of, name);
  else
    return std::string{name};
}

AddrPtr
FunctionSymbol::start_pc() const noexcept
{
  return pc_start;
}
AddrPtr
FunctionSymbol::end_pc() const noexcept
{
  return pc_end_exclusive;
}

FunctionSymbolSearchResult::FunctionSymbolSearchResult() noexcept : fn(nullptr) {}

FunctionSymbolSearchResult::FunctionSymbolSearchResult(FunctionSymbol *fn) noexcept : fn(fn) {}

FunctionSymbol &
FunctionSymbolSearchResult::value() const noexcept
{
  ASSERT(has_value(), "Search result had no value");
  return *fn;
}

FunctionSymbol *
FunctionSymbolSearchResult::operator->() const noexcept
{
  ASSERT(has_value(), "Search result had no value");
  return fn;
}

FunctionSymbol &
FunctionSymbolSearchResult::operator*() const noexcept
{
  return value();
}

bool
is_same(const FunctionSymbol *l, const FunctionSymbol *r) noexcept
{
  if (!l || !r)
    return false;
  return is_same(*l, *r);
}

bool
is_same(const FunctionSymbol &l, const FunctionSymbol &r) noexcept
{
  return l.name == r.name && l.pc_start == r.pc_start && l.pc_end_exclusive == r.pc_end_exclusive;
}

} // namespace sym
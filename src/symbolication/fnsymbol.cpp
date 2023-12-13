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

} // namespace sym
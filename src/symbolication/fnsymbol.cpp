#include "fnsymbol.h"
#include "symbolication/dwarf_expressions.h"
namespace sym {

ReturnValueClass
determine_ret_class(sym::Type *type) noexcept
{
  if (type->size() > 16) {
    return ReturnValueClass::ImplicitPointerToMemory;
  }
  return ReturnValueClass::Unknown;
}

FunctionSymbol::FunctionSymbol(AddrPtr start, AddrPtr end, std::string_view name, std::string_view member_of,
                               sym::Type *return_type, std::array<dw::IndexedDieReference, 3> maybe_origin,
                               CompilationUnit &decl_file, dw::FrameBaseExpression fb_expr,
                               std::optional<SourceCoordinate> &&source) noexcept
    : decl_file(NonNull(decl_file)), formal_parameters(start, end, {}), function_body_variables(),
      maybe_origin_dies(maybe_origin), framebase_expr(fb_expr), return_type(return_type), pc_start(start),
      pc_end_exclusive(end), member_of(member_of), name(name), source(std::move(source))
{
}

FunctionSymbol::FunctionSymbol(FunctionSymbol &&fn) noexcept
    : decl_file(fn.decl_file), formal_parameters(std::move(fn.formal_parameters)),
      function_body_variables(std::move(fn.function_body_variables)),
      maybe_origin_dies(std::move(fn.maybe_origin_dies)), framebase_expr(std::move(fn.framebase_expr)),
      return_type(fn.return_type), pc_start(fn.pc_start), pc_end_exclusive(fn.pc_end_exclusive),
      member_of(std::move(fn.member_of)), name(std::move(fn.name)), source(std::move(fn.source))
{
}

std::string
FunctionSymbol::build_full_name() const noexcept
{
  if (!(*member_of).empty()) {
    return fmt::format("{}::{}", member_of, name);
  } else {
    return std::string{name};
  }
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

const CompilationUnit *
FunctionSymbol::symbol_info() const noexcept
{
  return decl_file;
}

CompilationUnit *
FunctionSymbol::symbol_info() noexcept
{
  return decl_file;
}

std::span<const dw::IndexedDieReference>
FunctionSymbol::origin_dies() const noexcept
{
  auto &dies = *maybe_origin_dies;
  for (auto i = 0u; i < dies.size(); ++i) {
    if (!dies[i].valid()) {
      return std::span{dies.begin(), dies.begin() + i};
    }
  }
  return dies;
}

bool
FunctionSymbol::is_resolved() const noexcept
{
  return fully_parsed;
}

dw::FrameBaseExpression
FunctionSymbol::frame_base() const noexcept
{
  return framebase_expr;
}

const SymbolBlock &
FunctionSymbol::get_args() const noexcept
{
  return formal_parameters;
}

const std::vector<SymbolBlock> &
FunctionSymbol::get_frame_locals() const noexcept
{
  return function_body_variables;
}

u32
FunctionSymbol::local_variable_count() const noexcept
{
  return frame_locals_count;
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
  if (!l || !r) {
    return false;
  }
  return is_same(*l, *r);
}

bool
is_same(const FunctionSymbol &l, const FunctionSymbol &r) noexcept
{
  return *l.name == *r.name && *l.pc_start == *r.pc_start && *l.pc_end_exclusive == *r.pc_end_exclusive;
}

} // namespace sym
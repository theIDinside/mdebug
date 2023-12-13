#include "cu_symbol_info.h"
#include "../utils/filter.h"
#include "dwarf.h"
#include "dwarf/debug_info_reader.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "dwarf_defs.h"
#include "fnsymbol.h"
#include "objfile.h"
#include <array>
#include <list>
#include <span>

namespace sym {

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(dw::UnitData *data) noexcept
    : unit_data(data), line_table(), fns(), imported_units()
{
}

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(PartialCompilationUnitSymbolInfo &&o) noexcept
    : unit_data(o.unit_data), line_table(o.line_table), fns(std::move(o.fns)),
      imported_units(std::move(o.imported_units))
{
}

PartialCompilationUnitSymbolInfo &
PartialCompilationUnitSymbolInfo::operator=(PartialCompilationUnitSymbolInfo &&rhs) noexcept
{
  if (this == &rhs)
    return *this;
  unit_data = rhs.unit_data;
  line_table = rhs.line_table;
  fns = std::move(rhs.fns);
  imported_units = std::move(rhs.imported_units);
  return *this;
}

CompilationUnitSymbolInfo::CompilationUnitSymbolInfo(dw::UnitData *cu_data) noexcept
    : unit_data(cu_data), pc_start(nullptr), pc_end_exclusive(nullptr), line_table(), cu_name("unknown"), fns(),
      id()
{
}

CompilationUnitSymbolInfo::CompilationUnitSymbolInfo(CompilationUnitSymbolInfo &&from) noexcept
    : unit_data(from.unit_data), pc_start(from.pc_start), pc_end_exclusive(from.pc_end_exclusive),
      line_table(from.line_table), fns(std::move(from.fns)), imported_units(std::move(from.imported_units)),
      id(from.id)
{
}

CompilationUnitSymbolInfo &
CompilationUnitSymbolInfo::operator=(CompilationUnitSymbolInfo &&from) noexcept
{
  if (this == &from)
    return *this;
  unit_data = from.unit_data;
  pc_start = from.pc_start;
  pc_end_exclusive = from.pc_end_exclusive;
  line_table = from.line_table;
  fns = std::move(from.fns);
  imported_units = std::move(from.imported_units);
  id = from.id;
  return *this;
}

void
CompilationUnitSymbolInfo::set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept
{
  pc_start = lowest;
  pc_end_exclusive = end_exclusive;
}

void
CompilationUnitSymbolInfo::set_linetable(dw::LineTable table) noexcept
{
  line_table = table;
}

void
CompilationUnitSymbolInfo::set_id(SymbolInfoId info_id) noexcept
{
  id = info_id;
}

void
CompilationUnitSymbolInfo::set_name(std::string_view name) noexcept
{
  cu_name = name;
}

bool
CompilationUnitSymbolInfo::known_address_boundary() const noexcept
{
  return pc_start != nullptr && pc_end_exclusive != nullptr;
}

AddrPtr
CompilationUnitSymbolInfo::start_pc() const noexcept
{
  return pc_start;
}

AddrPtr
CompilationUnitSymbolInfo::end_pc() const noexcept
{
  return pc_end_exclusive;
}

std::string_view
CompilationUnitSymbolInfo::name() const noexcept
{
  return cu_name;
}

bool
CompilationUnitSymbolInfo::function_symbols_resolved() const noexcept
{
  return !fns.empty();
}

std::optional<sym::FunctionSymbol>
CompilationUnitSymbolInfo::get_fn_by_pc(AddrPtr pc) noexcept
{
  if (!function_symbols_resolved())
    resolve_fn_symbols();
  return std::nullopt;
}

dw::UnitData *
CompilationUnitSymbolInfo::get_dwarf_unit() const noexcept
{
  return unit_data;
}

enum class DieType
{
  Full,
  Declaration,
  Specification
};

void
CompilationUnitSymbolInfo::maybe_create_fn_symbol(StringOpt name, StringOpt mangled_name, AddrOpt low_pc,
                                                  AddrOpt high_pc) noexcept
{
  if ((name || mangled_name) && (low_pc && high_pc)) {
    auto &lo = low_pc.value();
    auto &hi = high_pc.value();
    if (name) {
      auto &n = name.value();
      fns.emplace_back(lo, hi, n);
    } else {
      fns.emplace_back(lo, hi, mangled_name.value());
    }
  } else {
    DLOG("mdb", "Warning! Incomplete function symbol. name={}, mangled_name={}, low_pc={}, high_pc={}",
         name.value_or("NONE"), mangled_name.value_or("NONE"), low_pc.value_or(nullptr),
         high_pc.value_or(nullptr));
  }
}

using DieOffset = u64;
using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;

struct ResolveFnSymbolState
{
  std::string_view name{};
  std::string_view mangled_name{};
  // a namespace or a class, so foo::foo, like a constructor, or utils::foo for a namespace with foo as a fn, for
  // instance.
  std::string_view namespace_ish{};
  AddrPtr low_pc = nullptr;
  AddrPtr high_pc = nullptr;
  u8 maybe_count;

  std::array<dw::IndexedDieReference, 3> maybe_origin_dies{};
  bool
  done(bool has_no_references) const
  {
    if (!name.empty()) {
      return low_pc != nullptr && high_pc != nullptr;
    } else if (!mangled_name.empty()) {
      // if we have die references, we are not done
      return has_no_references && low_pc != nullptr && high_pc != nullptr;
    } else {
      return false;
    }
  }

  sym::FunctionSymbol
  complete(Elf *elf) const
  {

    return sym::FunctionSymbol{.pc_start = elf->relocate_addr(low_pc),
                               .pc_end_exclusive = elf->relocate_addr(high_pc),
                               .member_of = "",
                               .name = name.empty() ? mangled_name : name,
                               .maybe_origin_dies = maybe_origin_dies};
  }

  void
  add_maybe_origin(dw::IndexedDieReference indexed) noexcept
  {
    if (maybe_count < 3) {
      maybe_origin_dies[maybe_count++] = indexed;
    }
  }
};

static std::optional<dw::DieReference>
follow_reference(ResolveFnSymbolState &state, dw::DieReference ref) noexcept
{
  std::optional<dw::DieReference> additional_die_reference = std::optional<dw::DieReference>{};
  dw::UnitReader reader{ref.cu};
  reader.seek_die(*ref.die);
  const auto &abbreviation = ref.cu->get_abbreviation(ref.die->abbreviation_code);
  if (!abbreviation.is_declaration)
    state.add_maybe_origin({.cu = ref.cu, .die_index = ref.cu->index_of(ref.die)});
  std::vector<i64> implicit_consts{};
  for (const auto &attr : abbreviation.attributes) {
    auto value = read_attribute_value(reader, attr, abbreviation.implicit_consts);
    switch (value.name) {
    case Attribute::DW_AT_name:
      state.name = value.string();
      break;
    case Attribute::DW_AT_linkage_name:
      state.mangled_name = value.string();
      break;
    // is address-representable?
    case Attribute::DW_AT_low_pc:
      state.low_pc = value.address();
      break;
    case Attribute::DW_AT_high_pc:
      if (value.form != AttributeForm::DW_FORM_addr)
        state.high_pc = state.low_pc.get() + value.address();
      else
        state.high_pc = value.address();
      break;
    case Attribute::DW_AT_specification:
    case Attribute::DW_AT_abstract_origin: {
      const auto declaring_die_offset = value.unsigned_value();
      additional_die_reference = ref.cu->get_objfile()->get_die_reference(declaring_die_offset);
    } break;
    default:
      break;
    }
  }
  return additional_die_reference;
}

void
CompilationUnitSymbolInfo::resolve_fn_symbols() noexcept
{
  auto elf = unit_data->get_objfile()->parsed_elf;
  const auto &dies = unit_data->get_dies();
  constexpr auto program_dies = [](const auto &die) {
    switch (die.tag) {
    case DwarfTag::DW_TAG_subprogram:
    case DwarfTag::DW_TAG_inlined_subroutine:
      return true;
    default:
      return false;
    }
  };

  dw::UnitReader reader{unit_data};
  // For a function symbol, we want to record a DIE, from which we can reach all it's (possible) references.
  // Unfortunately DWARF doesn't seem to define a "OWNING" die. Which is... unfortunate. So we have to guess. But
  // 2-3 should be enough.
  for (const auto &die : utils::FilterView(dies, program_dies)) {
    const auto &abbreviation = unit_data->get_abbreviation(die.abbreviation_code);
    // Skip declarations - we will visit them if necessary, but on their own they can't tell us anything.
    if (abbreviation.is_declaration) {
      continue;
    }
    reader.seek_die(die);
    std::vector<i64> implicit_consts{};
    ResolveFnSymbolState state{};
    std::list<dw::DieReference> die_refs{};
    for (const auto &attr : abbreviation.attributes) {
      auto value = read_attribute_value(reader, attr, abbreviation.implicit_consts);
      switch (value.name) {
      case Attribute::DW_AT_name:
        state.name = value.string();
        break;
      case Attribute::DW_AT_linkage_name:
        state.mangled_name = value.string();
        break;
      case Attribute::DW_AT_low_pc:
        state.low_pc = value.address();
        break;
      case Attribute::DW_AT_high_pc:
        if (value.form != AttributeForm::DW_FORM_addr) {
          state.high_pc = state.low_pc.get() + value.address();
        } else
          state.high_pc = value.address();
        break;
      case Attribute::DW_AT_specification:
      case Attribute::DW_AT_abstract_origin: {
        const auto declaring_die_offset = value.unsigned_value();
        if (auto die_ref = unit_data->get_objfile()->get_die_reference(declaring_die_offset); die_ref)
          die_refs.push_back(*die_ref);
        else
          DLOG("mdb", "Could not find die reference");
      } break;
      default:
        break;
      }
    }
    state.add_maybe_origin(dw::IndexedDieReference{unit_data, unit_data->index_of(&die)});
    if (state.done(die_refs.empty())) {
      fns.emplace_back(state.complete(elf));
    } else {
      // reset e = end() at each iteration, because we might have extended the list during iteration.
      for (auto it = die_refs.begin(), e = die_refs.end(); it != e; ++it) {
        auto new_ref = follow_reference(state, *it);
        // we use a linked list here, *specifically* so we can push back references while iterating.
        if (new_ref) {
          die_refs.push_back(*new_ref);
          e = die_refs.end();
        }

        if (state.done(std::distance(++auto{it}, e) == 0)) {
          fns.emplace_back(state.complete(elf));
          break;
        }
      }
    }
  }
  std::sort(fns.begin(), fns.end(), FunctionSymbol::Sorter());
}

} // namespace sym
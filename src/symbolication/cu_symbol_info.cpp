#include "cu_symbol_info.h"
#include "dwarf.h"
#include "dwarf/debug_info_reader.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "fmt/format.h"
#include "fnsymbol.h"
#include "objfile.h"
#include "symbolication/dwarf_defs.h"
#include "symbolication/dwarf_expressions.h"
#include <array>
#include <list>
#include <utils/filter.h>

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

SourceFileSymbolInfo::SourceFileSymbolInfo(dw::UnitData *cu_data) noexcept
    : unit_data(cu_data), pc_start(nullptr), pc_end_exclusive(nullptr), line_table(), cu_name("unknown"), fns()
{
}

void
SourceFileSymbolInfo::set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept
{
  pc_start = lowest;
  pc_end_exclusive = end_exclusive;
}

// the line table consists of a list of directory entries and file entries
// that are relevant for this line table. As such, we are informed of all the
// source files used over some range of addressess etc. These source files
// might be included in multiple places (compilation units). We de-duplicate them
// by storing them by name in `ObjectFile` in a map and then add the references to them
// to the newly minted compilation unit handle (process_source_code_files)
void
SourceFileSymbolInfo::process_source_code_files(u64 table) noexcept
{
  line_table = table;
  auto obj = unit_data->get_objfile();
  auto header = unit_data->get_objfile()->get_lnp_header(line_table);
  for (auto &&file : header->files()) {
    std::string_view path{file.c_str()};
    auto source_code_file = obj->get_source_file(path);
    add_source_file(std::move(source_code_file));
  }
}

void
SourceFileSymbolInfo::add_source_file(std::shared_ptr<dw::SourceCodeFile> &&src_file) noexcept
{
  source_code_files.emplace_back(std::move(src_file));
}

std::span<std::shared_ptr<dw::SourceCodeFile>>
SourceFileSymbolInfo::sources() noexcept
{
  return source_code_files;
}

void
SourceFileSymbolInfo::set_name(std::string_view name) noexcept
{
  cu_name = name;
}

bool
SourceFileSymbolInfo::known_address_boundary() const noexcept
{
  return pc_start != nullptr && pc_end_exclusive != nullptr;
}

AddrPtr
SourceFileSymbolInfo::start_pc() const noexcept
{
  return pc_start;
}

AddrPtr
SourceFileSymbolInfo::end_pc() const noexcept
{
  return pc_end_exclusive;
}

std::string_view
SourceFileSymbolInfo::name() const noexcept
{
  return cu_name;
}

bool
SourceFileSymbolInfo::function_symbols_resolved() const noexcept
{
  return !fns.empty();
}

sym::FunctionSymbol *
SourceFileSymbolInfo::get_fn_by_pc(AddrPtr pc) noexcept
{
  if (!function_symbols_resolved())
    resolve_fn_symbols();

  auto iter = std::find_if(fns.begin(), fns.end(),
                           [pc](sym::FunctionSymbol &fn) { return fn.start_pc() <= pc && pc < fn.end_pc(); });
  if (iter != std::end(fns)) {
    return iter.base();
  }
  return nullptr;
}

dw::UnitData *
SourceFileSymbolInfo::get_dwarf_unit() const noexcept
{
  return unit_data;
}

std::optional<dw::LineTable>
SourceFileSymbolInfo::get_linetable() noexcept
{
  return unit_data->get_objfile()->get_linetable(line_table);
}

std::optional<Path>
SourceFileSymbolInfo::get_lnp_file(u32 index) noexcept
{
  // TODO(simon): we really should store a pointer to the line number program table (or header) in either UnitData
  // or SourceFileSymbolInfo directly.
  return unit_data->get_objfile()->get_lnp_header(line_table)->file(index);
}

using DieOffset = u64;
using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;

struct ResolveFnSymbolState
{
  SourceFileSymbolInfo *symtab;
  std::string_view name{};
  std::string_view mangled_name{};
  // a namespace or a class, so foo::foo, like a constructor, or utils::foo for a namespace with foo as a fn, for
  // instance.
  std::string_view namespace_ish{};
  AddrPtr low_pc{nullptr};
  AddrPtr high_pc{nullptr};
  u8 maybe_count{0};
  std::optional<std::span<const u8>> frame_base_description{};
  sym::Type *ret_type{nullptr};

  std::optional<u32> line{std::nullopt};
  std::optional<std::string> lnp_file{std::nullopt};

  explicit ResolveFnSymbolState(SourceFileSymbolInfo *symtable) noexcept : symtab(symtable) {}

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
  complete(Elf *elf)
  {
    std::optional<SourceCoordinate> source = lnp_file.transform(
        [&](auto &&path) { return SourceCoordinate{.path = std::move(path), .line = this->line.value_or(0)}; });
    if (lnp_file) {
      ASSERT(lnp_file.value().empty(), "Should have moved std string!");
    }
    if (source) {
      DLOG("mdb", "fn {} is defined in {}", name.empty() ? mangled_name : name, source.value().path);
    }
    return sym::FunctionSymbol{elf->relocate_addr(low_pc),
                               elf->relocate_addr(high_pc),
                               name.empty() ? mangled_name : name,
                               namespace_ish,
                               ret_type,
                               maybe_origin_dies,
                               *symtab,
                               dw::FrameBaseExpression::Take(frame_base_description),
                               std::move(source)};
  }

  void
  add_maybe_origin(dw::IndexedDieReference indexed) noexcept
  {
    if (maybe_count < 3 && !std::any_of(maybe_origin_dies.begin(), maybe_origin_dies.begin() + maybe_count,
                                        [&](const auto &idr) { return idr == indexed; })) {
      maybe_origin_dies[maybe_count++] = indexed;
    }
  }
};

static std::optional<dw::DieReference>
follow_reference(SourceFileSymbolInfo &src_file, ResolveFnSymbolState &state, dw::DieReference ref) noexcept
{
  std::optional<dw::DieReference> additional_die_reference = std::optional<dw::DieReference>{};
  dw::UnitReader reader{ref.cu};
  reader.seek_die(*ref.die);
  const auto &abbreviation = ref.cu->get_abbreviation(ref.die->abbreviation_code);
  if (!abbreviation.is_declaration)
    state.add_maybe_origin({.cu = ref.cu, .die_index = ref.cu->index_of(ref.die)});

  if (const auto parent = ref.die->parent();
      maybe_null_any_of<DwarfTag::DW_TAG_class_type, DwarfTag::DW_TAG_structure_type>(parent)) {
    dw::DieReference parent_ref{.cu = ref.cu, .die = parent};
    if (auto class_name = parent_ref.read_attribute(Attribute::DW_AT_name); class_name) {
      state.namespace_ish = class_name->string();
    }
  }

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
    case Attribute::DW_AT_decl_file: {
      if (!state.lnp_file) {
        ASSERT(ref.cu == src_file.get_dwarf_unit(), "Cross CU requires another LNP. This will be wrong.");
        state.lnp_file =
            src_file.get_lnp_file(value.unsigned_value()).transform([](auto &&p) { return p.string(); });
      }
    } break;
    case Attribute::DW_AT_decl_line:
      if (!state.line) {
        state.line = value.unsigned_value();
      }
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
SourceFileSymbolInfo::resolve_fn_symbols() noexcept
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
    ResolveFnSymbolState state{this};
    std::list<dw::DieReference> die_refs{};
    for (const auto &attr : abbreviation.attributes) {
      auto value = read_attribute_value(reader, attr, abbreviation.implicit_consts);
      switch (value.name) {
      case Attribute::DW_AT_frame_base:
        state.frame_base_description = as_span(value.block());
        break;
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
      case Attribute::DW_AT_decl_file: {
        ASSERT(!state.lnp_file.has_value(), "lnp file has been set already, to {}, new {}", state.lnp_file.value(),
               value.unsigned_value());
        state.lnp_file = this->get_lnp_file(value.unsigned_value()).transform([](auto &&p) { return p.string(); });
      } break;
      case Attribute::DW_AT_decl_line:
        ASSERT(!state.line.has_value(), "file line number has been set already, to {}, new {}", state.line.value(),
               value.unsigned_value());
        state.line = value.unsigned_value();
        break;
      case Attribute::DW_AT_specification:
      case Attribute::DW_AT_abstract_origin: {
        const auto declaring_die_offset = value.unsigned_value();
        if (auto die_ref = unit_data->get_objfile()->get_die_reference(declaring_die_offset); die_ref)
          die_refs.push_back(*die_ref);
        else {
          DLOG("mdb", "Could not find die reference");
        }
        break;
      }
      case Attribute::DW_AT_type: {
        const auto type_id = value.unsigned_value();
        auto obj = unit_data->get_objfile();
        const auto ref = obj->get_die_reference(type_id);
        state.ret_type = obj->types->get_or_prepare_new_type(ref->as_indexed());
        break;
      }
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
        auto new_ref = follow_reference(*this, state, *it);
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

AddressToCompilationUnitMap::AddressToCompilationUnitMap() noexcept : mutex(), mapping() {}

std::vector<sym::dw::UnitData *>
AddressToCompilationUnitMap::find_by_pc(AddrPtr pc) noexcept
{
  if (auto res = mapping.find(pc); res) {
    auto result = std::move(res.value());
    return result;
  } else {
    return {};
  }
}

void
AddressToCompilationUnitMap::add_cus(const std::span<SourceFileSymbolInfo> &cus) noexcept
{
  std::lock_guard lock(mutex);
  for (const auto &src_sym_info : cus) {
    add_cu(src_sym_info.start_pc(), src_sym_info.end_pc(), src_sym_info.get_dwarf_unit());
  }
}

void
AddressToCompilationUnitMap::add_cu(AddrPtr start, AddrPtr end, sym::dw::UnitData *cu) noexcept
{
  mapping.add_mapping(start, end, cu);
}

} // namespace sym
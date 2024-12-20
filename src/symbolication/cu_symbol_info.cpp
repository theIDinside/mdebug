#include "cu_symbol_info.h"
#include "dwarf.h"
#include "dwarf/debug_info_reader.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "fnsymbol.h"
#include "objfile.h"
#include "symbolication/dwarf/die_ref.h"
#include "symbolication/dwarf_defs.h"
#include <array>
#include <list>
#include <utils/filter.h>

namespace sym {

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(dw::UnitData *data) noexcept
    : unit_data(data), fns(), imported_units()
{
}

PartialCompilationUnitSymbolInfo::PartialCompilationUnitSymbolInfo(PartialCompilationUnitSymbolInfo &&o) noexcept
    : unit_data(o.unit_data), fns(std::move(o.fns)), imported_units(std::move(o.imported_units))
{
}

PartialCompilationUnitSymbolInfo &
PartialCompilationUnitSymbolInfo::operator=(PartialCompilationUnitSymbolInfo &&rhs) noexcept
{
  if (this == &rhs) {
    return *this;
  }
  unit_data = rhs.unit_data;
  fns = std::move(rhs.fns);
  imported_units = std::move(rhs.imported_units);
  return *this;
}

CompilationUnit::CompilationUnit(dw::UnitData *cu_data) noexcept
    : unit_data(cu_data), pc_start(nullptr), pc_end_exclusive(nullptr), line_table(), cu_name("unknown"), fns()
{
}

void
CompilationUnit::set_address_boundary(AddrPtr lowest, AddrPtr end_exclusive) noexcept
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
CompilationUnit::ProcessSourceCodeFiles(u64 table) noexcept
{
  line_table = table;
  auto obj = unit_data->GetObjectFile();
  auto header = unit_data->GetObjectFile()->GetLineNumberProgramHeader(line_table);
  if (!header) {
    return;
  }
  DBGLOG(dwarf, "retrieving files from line number program @ {} for cu=0x{:x} '{}'", header->sec_offset,
         unit_data->section_offset(), cu_name);

  for (const auto &[fullPath, v] : header->FileEntries()) {
    auto source_code_file = obj->GetSourceCodeFile(fullPath);
    add_source_file(std::move(source_code_file));
  }
}

void
CompilationUnit::add_source_file(std::shared_ptr<dw::SourceCodeFile> &&src_file) noexcept
{
  source_code_files.emplace_back(std::move(src_file));
}

std::span<const std::shared_ptr<dw::SourceCodeFile>>
CompilationUnit::sources() const noexcept
{
  return source_code_files;
}

void
CompilationUnit::set_name(std::string_view name) noexcept
{
  cu_name = name;
}

bool
CompilationUnit::known_address_boundary() const noexcept
{
  return pc_start != nullptr && pc_end_exclusive != nullptr;
}

AddrPtr
CompilationUnit::StartPc() const noexcept
{
  return pc_start;
}

AddrPtr
CompilationUnit::EndPc() const noexcept
{
  return pc_end_exclusive;
}

std::string_view
CompilationUnit::name() const noexcept
{
  return cu_name;
}

bool
CompilationUnit::function_symbols_resolved() const noexcept
{
  return !fns.empty();
}

sym::FunctionSymbol *
CompilationUnit::get_fn_by_pc(AddrPtr pc) noexcept
{
  if (!function_symbols_resolved()) {
    resolve_fn_symbols();
  }

  auto iter = std::find_if(fns.begin(), fns.end(),
                           [pc](sym::FunctionSymbol &fn) { return fn.StartPc() <= pc && pc < fn.EndPc(); });
  if (iter != std::end(fns)) {
    return iter.base();
  }
  return nullptr;
}

dw::UnitData *
CompilationUnit::get_dwarf_unit() const noexcept
{
  return unit_data;
}

std::optional<Path>
CompilationUnit::get_lnp_file(u32 index) noexcept
{
  // TODO(simon): we really should store a pointer to the line number program table (or header) in either UnitData
  // or SourceFileSymbolInfo directly.
  return unit_data->GetObjectFile()->GetLineNumberProgramHeader(line_table)->file(index);
}

using DieOffset = u64;
using StringOpt = std::optional<std::string_view>;
using AddrOpt = std::optional<AddrPtr>;

struct ResolveFnSymbolState
{
  CompilationUnit *symtab;
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

  explicit ResolveFnSymbolState(CompilationUnit *symtable) noexcept : symtab(symtable) {}

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
  complete()
  {
    std::optional<SourceCoordinate> source =
      lnp_file.transform([&](auto &&path) { return SourceCoordinate{std::move(path), line.value_or(0), 0}; });
    if (lnp_file) {
      ASSERT(lnp_file.value().empty(), "Should have moved std string!");
    }

    return sym::FunctionSymbol{low_pc,
                               high_pc,
                               name.empty() ? mangled_name : name,
                               namespace_ish,
                               ret_type,
                               maybe_origin_dies,
                               *symtab,
                               frame_base_description.value_or(std::span<const u8>{}),
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
follow_reference(CompilationUnit &src_file, ResolveFnSymbolState &state, dw::DieReference ref) noexcept
{
  std::optional<dw::DieReference> additional_die_reference = std::optional<dw::DieReference>{};
  dw::UnitReader reader = ref.GetReader();
  const auto &abbreviation = ref.GetUnitData()->get_abbreviation(ref.GetDie()->abbreviation_code);
  if (!abbreviation.is_declaration) {
    state.add_maybe_origin(ref.AsIndexed());
  }

  if (const auto parent = ref.GetDie()->parent();
      maybe_null_any_of<DwarfTag::DW_TAG_class_type, DwarfTag::DW_TAG_structure_type>(parent)) {
    dw::DieReference parentReference{ref.GetUnitData(), parent};
    if (auto class_name = parentReference.read_attribute(Attribute::DW_AT_name); class_name) {
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
        state.lnp_file =
          src_file.get_lnp_file(value.unsigned_value()).transform([](auto &&p) { return p.string(); });
        CDLOG(ref.GetUnitData() != src_file.get_dwarf_unit(), core,
              "[dwarf]: Cross CU requires (?) another LNP. ref.cu = 0x{:x}, src file cu=0x{:x}",
              ref.GetUnitData()->section_offset(), src_file.get_dwarf_unit()->section_offset());
      }
    } break;
    case Attribute::DW_AT_decl_line:
      if (!state.line) {
        state.line = value.unsigned_value();
      }
      break;
    case Attribute::DW_AT_high_pc:
      if (value.form != AttributeForm::DW_FORM_addr) {
        state.high_pc = state.low_pc.get() + value.address();
      } else {
        state.high_pc = value.address();
      }
      break;
    case Attribute::DW_AT_specification:
    case Attribute::DW_AT_abstract_origin: {
      const auto declaring_die_offset = value.unsigned_value();
      additional_die_reference = ref.GetUnitData()->GetObjectFile()->GetDebugInfoEntryReference(declaring_die_offset);
    } break;
    default:
      break;
    }
  }
  return additional_die_reference;
}

void
CompilationUnit::resolve_fn_symbols() noexcept
{
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
        } else {
          state.high_pc = value.address();
        }
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
        if (auto die_ref = unit_data->GetObjectFile()->GetDebugInfoEntryReference(declaring_die_offset); die_ref) {
          die_refs.push_back(*die_ref);
        } else {
          DBGLOG(core, "Could not find die reference");
        }
        break;
      }
      case Attribute::DW_AT_type: {
        const auto type_id = value.unsigned_value();
        auto obj = unit_data->GetObjectFile();
        const auto ref = obj->GetDebugInfoEntryReference(type_id);
        state.ret_type = obj->GetTypeStorage()->GetOrCreateNewType(ref->AsIndexed());
        break;
      }
      default:
        break;
      }
    }

    state.add_maybe_origin(dw::IndexedDieReference{unit_data, unit_data->index_of(&die)});
    if (state.done(die_refs.empty())) {
      fns.emplace_back(state.complete());
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
          fns.emplace_back(state.complete());
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
AddressToCompilationUnitMap::add_cus(const std::span<CompilationUnit> &cus) noexcept
{
  std::lock_guard lock(mutex);
  for (const auto &src_sym_info : cus) {
    add_cu(src_sym_info.StartPc(), src_sym_info.EndPc(), src_sym_info.get_dwarf_unit());
  }
}

void
AddressToCompilationUnitMap::add_cu(AddrPtr start, AddrPtr end, sym::dw::UnitData *cu) noexcept
{
  mapping.add_mapping(start, end, cu);
}

} // namespace sym
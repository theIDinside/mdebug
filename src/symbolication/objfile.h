#pragma once
#include "block.h"
#include "cu_symbol_info.h"
#include "elf.h"
#include "elf_symbols.h"
#include "interface/dap/types.h"
#include "mdb_config.h"
#include "symbolication/dwarf/lnp.h"
#include <common.h>
#include <regex>
#include <string_view>
#include <sys/mman.h>

using VariablesReference = int;
template <typename T> using Set = std::unordered_set<T>;

class NonExecutableCompilationUnitFile;

template <typename T> using Optional = std::optional<T>;

namespace sym {
class Unwinder;
class Type;
class Value;
class ValueVisualizer;
class ValueResolver;
enum class VariableSet : u8;
enum class FrameVariableKind : u8;

namespace dw {
struct LNPHeader;
class UnitData;
class LineTable;
struct DieReference;
struct ObjectFileNameIndex;
} // namespace dw
} // namespace sym

class Elf;
class SymbolFile;
struct ElfSection;

struct BreakpointLookup
{
  AddrPtr address;
  std::optional<LocationSourceInfo> loc_src_info;
};

/**
 * The owning data-structure that all debug info symbols point to. The ObjFile is meant
 * to outlive them all, so it's safe to take raw pointers into `loaded_binary`.
 */
struct ObjectFile
{
  friend SymbolFile;
  Immutable<Path> path;
  Immutable<std::string> objfile_id;
  Immutable<u64> size;
  const u8 *loaded_binary;
  bool has_elf_symbols = false;
  Elf *elf{nullptr};
  bool initialized{false};
  std::unique_ptr<sym::Unwinder> unwinder{nullptr};

  // Address bounds determined by reading the program segments of the elf binary
  AddressRange unrelocated_address_bounds{};
  std::unique_ptr<TypeStorage> types;

  ObjectFile(std::string objfile_id, Path p, u64 size, const u8 *loaded_binary) noexcept;
  ~ObjectFile() noexcept;

  template <typename T>
  auto
  get_at_offset(u64 offset) -> T *
  {
    return (T *)(loaded_binary + offset);
  }

  template <typename T>
  auto
  get_at(const u8 *ptr) -> const T *
  {
    ASSERT(ptr > loaded_binary, "Pointer is outside (below) memory mapped object file by {} bytes at {:p}",
           (u64)(loaded_binary - ptr), (void *)ptr);
    ASSERT(ptr < (loaded_binary + *size),
           "Pointer is outside (above) memory mapped object file by {} bytes at {:p}", (u64)(ptr - loaded_binary),
           (void *)ptr);
    return (T *)(ptr);
  }

  auto get_offset(u8 *ptr) const noexcept -> u64;
  auto get_section(Elf *elf, u32 index) const noexcept -> u8 *;
  auto text_section_offset() const noexcept -> AddrPtr;
  auto get_min_fn_sym(std::string_view name) noexcept -> std::optional<MinSymbol>;
  auto search_minsym_fn_info(AddrPtr pc) noexcept -> const MinSymbol *;
  auto get_min_obj_sym(std::string_view name) noexcept -> std::optional<MinSymbol>;

  auto set_unit_data(const std::vector<sym::dw::UnitData *> &unit_data) noexcept -> void;
  auto compilation_units() noexcept -> std::vector<sym::dw::UnitData *> &;
  auto get_cu_from_offset(u64 offset) noexcept -> sym::dw::UnitData *;
  auto get_die_reference(u64 offset) noexcept -> std::optional<sym::dw::DieReference>;
  auto name_index() noexcept -> sym::dw::ObjectFileNameIndex *;

  auto get_lnp_header(u64 offset) noexcept -> sym::dw::LNPHeader *;
  auto read_lnp_headers() noexcept -> void;
  auto get_lnp_headers() noexcept -> std::span<sym::dw::LNPHeader>;
  auto add_parsed_ltes(const std::span<sym::dw::LNPHeader> &headers,
                       std::vector<sym::dw::ParsedLineTableEntries> &&parsed_ltes) noexcept -> void;

  auto init_lnp_storage(const std::span<sym::dw::LNPHeader> &headers) -> void;
  auto get_plte(u64 offset) noexcept -> sym::dw::ParsedLineTableEntries &;
  auto add_initialized_cus(std::span<sym::CompilationUnit> new_cus) noexcept -> void;

  auto get_source_file(const std::filesystem::path &fullpath) noexcept -> std::shared_ptr<sym::dw::SourceCodeFile>;
  auto source_code_files() noexcept -> std::vector<sym::dw::SourceCodeFile> &;
  auto source_units() noexcept -> std::vector<sym::CompilationUnit> &;

  auto initial_dwarf_setup(const sys::DwarfParseConfiguration &config) noexcept -> void;
  auto add_elf_symbols(std::vector<MinSymbol> &&fn_symbols,
                       std::unordered_map<std::string_view, MinSymbol> &&obj_symbols) noexcept -> void;

  auto init_minsym_name_lookup() noexcept -> void;

  auto find_custom_visualizer(sym::Type &type) noexcept -> std::unique_ptr<sym::ValueVisualizer>;
  auto find_custom_resolver(sym::Type &type) noexcept -> std::unique_ptr<sym::ValueResolver>;
  auto init_visualizer(std::shared_ptr<sym::Value> &value) noexcept -> void;
  auto regex_search(const std::string &regex_pattern) const noexcept -> std::vector<std::string>;

private:
  auto get_cus_from_pc(AddrPtr pc) noexcept -> std::vector<sym::dw::UnitData *>;
  // TODO(simon): Implement something more efficient. For now, we do the absolute worst thing, but this problem is
  // uninteresting for now and not really important, as it can be fixed at any point in time.
  auto get_source_infos(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>;
  auto relocated_get_source_code_files(AddrPtr base, AddrPtr pc) noexcept
      -> std::vector<sym::dw::RelocatedSourceCodeFile>;

  std::unordered_map<std::string_view, Index> minimal_fn_symbols;
  std::vector<MinSymbol> min_fn_symbols_sorted;
  std::unordered_map<std::string_view, MinSymbol> minimal_obj_symbols;

  std::mutex unit_data_write_lock;
  std::vector<sym::dw::UnitData *> dwarf_units;
  std::unique_ptr<sym::dw::ObjectFileNameIndex> name_to_die_index;

  std::mutex parsed_lte_write_lock;
  std::vector<sym::dw::LineTable> line_table;
  std::shared_ptr<std::vector<sym::dw::LNPHeader>> lnp_headers;
  std::shared_ptr<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>> parsed_ltes;

  std::mutex cu_write_lock;
  std::vector<sym::CompilationUnit> comp_units;

  // TODO(simon): use std::string_view here instead of std::filesystem::path, the std::string_view
  //   can actually reference the path in sym::dw::SourceCodeFile if it is made stable
  std::unordered_map<std::filesystem::path, std::shared_ptr<sym::dw::SourceCodeFile>> lnp_source_code_files;

  sym::AddressToCompilationUnitMap addr_cu_map;
  std::unordered_map<int, SharedPtr<sym::Value>> valobj_cache;
};

class SymbolFile
{
  std::shared_ptr<ObjectFile> binary_object;
  std::unordered_map<int, SharedPtr<sym::Value>> valobj_cache{};

public:
  using shr_ptr = std::shared_ptr<SymbolFile>;
  Immutable<std::string> obj_id;
  Immutable<AddrPtr> baseAddress;
  Immutable<AddressRange> pc_bounds;
  SymbolFile(std::string obj_id, std::shared_ptr<ObjectFile> &&binary, AddrPtr relocated_base) noexcept;

  static shr_ptr Create(Pid process_id, std::shared_ptr<ObjectFile> binary, AddrPtr relocated_base) noexcept;
  auto copy(const TraceeController &tc, AddrPtr relocated_base) const noexcept -> std::shared_ptr<SymbolFile>;
  auto getCusFromPc(AddrPtr pc) noexcept -> std::vector<sym::dw::UnitData *>;

  auto objectFile() const noexcept -> ObjectFile *;
  auto symbolFileId() const noexcept -> std::string_view;
  auto contains(AddrPtr pc) const noexcept -> bool;
  auto unrelocate(AddrPtr pc) const noexcept -> AddrPtr;

  // Clears the variablesReference cache - not that this doesn't necessarily mean the objects will die; it only
  // mean that from a Variables Reference standpoint, they're no longer reachable. For instance, in the future, we
  // might open for extending the debugger so that the user can do scripts etc, and they might want to hold on to
  // values for longer than a "stop". but since our cache contains `std::shared_ptr<Value>` this will be ok, if the
  // user will have created something that holds a reference to the value it will now become the sole owner.
  auto invalidateVariableReferences() noexcept -> void;
  auto registerResolver(std::shared_ptr<sym::Value> &value) noexcept -> void;
  auto getVariables(TraceeController &tc, sym::Frame &frame, sym::VariableSet set) noexcept
      -> std::vector<ui::dap::Variable>;
  auto getSourceInfos(AddrPtr pc) noexcept -> std::vector<sym::CompilationUnit *>;
  auto getSourceCodeFiles(AddrPtr pc) noexcept -> std::vector<sym::dw::RelocatedSourceCodeFile>;
  auto resolve(TraceeController &tc, int ref, std::optional<u32> start, std::optional<u32> count) noexcept
      -> std::vector<ui::dap::Variable>;

  auto low_pc() noexcept -> AddrPtr;
  auto high_pc() noexcept -> AddrPtr;

  auto getMinimalFnSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>;
  auto searchMinSymFnInfo(AddrPtr pc) noexcept -> const MinSymbol *;
  auto getMinimalSymbol(std::string_view name) noexcept -> std::optional<MinSymbol>;
  auto cacheValue(VariablesReference ref, std::shared_ptr<sym::Value> value) noexcept -> void;
  auto getLineTable(u64 offset) noexcept -> sym::dw::LineTable;
  auto path() const noexcept -> Path;

  auto lookup_by_spec(const FunctionBreakpointSpec &spec) noexcept -> std::vector<BreakpointLookup>;

private:
  std::vector<ui::dap::Variable> getVariablesImpl(sym::FrameVariableKind variables_kind, TraceeController &tc,
                                                  sym::Frame &frame) noexcept;
};

ObjectFile *mmap_objectfile(const TraceeController &tc, const Path &path) noexcept;
std::shared_ptr<ObjectFile> CreateObjectFile(Pid process_id, const Path &path) noexcept;

struct UnloadObjectFile
{
  void
  operator()(ObjectFile *obj)
  {
    munmap((void *)obj->loaded_binary, obj->size);
    obj->loaded_binary = nullptr;
    obj->size = 0;
    obj->path = "";
  }
};

void object_file_unloader(ObjectFile *obj);
#pragma once
#include "../common.h"
#include "block.h"
#include "cu_symbol_info.h"
#include "dwarf.h"
#include "dwarf/die.h"
#include "dwarf/lnp.h"
#include "elf.h"
#include "elf_symbols.h"
#include "lnp.h"
#include <string_view>
#include <sys/mman.h>

class CompilationUnitFile;
class NonExecutableCompilationUnitFile;

namespace sym {
class Unwinder;
class Type;

namespace dw {
struct LNPHeader;
class UnitData;
class LineTable;
struct DieReference;
struct ObjectFileNameIndex;
} // namespace dw
} // namespace sym

class Elf;
struct ElfSection;

/**
 * The owning data-structure that all debug info symbols point to. The ObjFile is meant
 * to outlive them all, so it's safe to take raw pointers into `loaded_binary`.
 */
struct ObjectFile
{
  Path path;
  u64 size;
  const u8 *loaded_binary;
  Elf *parsed_elf = nullptr;
  bool min_syms = false;
  std::unordered_map<std::string_view, MinSymbol> minimal_fn_symbols;
  std::unordered_map<std::string_view, MinSymbol> minimal_obj_symbols;

  // Should the key be something much better than a string, here? If so, how and what?
  std::unordered_map<u64, sym::Type> types;

  std::vector<LineTable> line_tables;
  std::vector<LineHeader> line_table_headers;
  sym::Unwinder *unwinder;
  // Address bounds determined by reading the program segments of the elf binary
  AddressRange address_bounds;
  std::vector<CompilationUnitFile> m_full_cu;
  std::vector<NonExecutableCompilationUnitFile> m_partial_units;

  ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept;
  ~ObjectFile() noexcept;

  template <typename T>
  T *
  get_at_offset(u64 offset)
  {
    return (T *)(loaded_binary + offset);
  }

  template <typename T>
  const T *
  get_at(const u8 *ptr)
  {
    ASSERT(ptr > loaded_binary, "Pointer is outside (below) memory mapped object file by {} bytes at {:p}",
           (u64)(loaded_binary - ptr), (void *)ptr);
    ASSERT(ptr < (loaded_binary + size),
           "Pointer is outside (above) memory mapped object file by {} bytes at {:p}", (u64)(ptr - loaded_binary),
           (void *)ptr);
    return (T *)(ptr);
  }

  u64 get_offset(u8 *ptr) const noexcept;
  u8 *get_section(Elf *elf, u32 index) const noexcept;
  AddrPtr text_section_offset() const noexcept;
  std::optional<MinSymbol> get_min_fn_sym(std::string_view name) noexcept;
  std::optional<MinSymbol> get_min_obj_sym(std::string_view name) noexcept;

  Path interpreter() const noexcept;
  bool found_min_syms() const noexcept;
  LineHeader *line_table_header(u64 offset) noexcept;
  SearchResult<CompilationUnitFile> get_cu_iterable(AddrPtr addr) const noexcept;
  void set_unit_data(const std::vector<sym::dw::UnitData *> &unit_data) noexcept;
  std::vector<sym::dw::UnitData *> &compilation_units() noexcept;
  sym::dw::UnitData *get_cu_from_offset(u64 offset) noexcept;
  std::optional<sym::dw::DieReference> get_die_reference(u64 offset) noexcept;
  sym::dw::ObjectFileNameIndex *name_index() noexcept;

  sym::dw::LNPHeader *get_lnp_header(u64 offset) noexcept;
  sym::dw::LineTable get_linetable(u64 offset) noexcept;
  void read_lnp_headers() noexcept;
  std::span<sym::dw::LNPHeader> get_lnp_headers() noexcept;
  void add_parsed_ltes(const std::span<sym::dw::LNPHeader> &headers,
                       std::vector<sym::dw::ParsedLineTableEntries> &&parsed_ltes);
  void add_initialized_cus(std::span<sym::SourceFileSymbolInfo> new_cus) noexcept;
  std::vector<sym::SourceFileSymbolInfo> &source_units() noexcept;
  std::vector<sym::dw::UnitData *> get_cus_from_pc(AddrPtr pc) noexcept;

private:
  std::mutex unit_data_write_lock;
  std::vector<sym::dw::UnitData *> dwarf_units;
  std::unique_ptr<sym::dw::ObjectFileNameIndex> name_to_die_index;

  std::mutex parsed_lte_write_lock;
  std::vector<sym::dw::LineTable> line_table;
  std::shared_ptr<std::vector<sym::dw::LNPHeader>> lnp_headers;
  std::shared_ptr<std::unordered_map<u64, sym::dw::ParsedLineTableEntries>> parsed_ltes;

  std::mutex cu_write_lock;
  std::vector<sym::SourceFileSymbolInfo> comp_units;

  std::mutex block_array_write_lock;
  std::vector<sym::BlockArray> block_array;

  sym::AddressToCompilationUnitMap addr_cu_map;
};

ObjectFile *mmap_objectfile(const Path &path) noexcept;

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
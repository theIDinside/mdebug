#pragma once
#include "../common.h"
#include "dwarf.h"
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
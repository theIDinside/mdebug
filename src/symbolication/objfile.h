#pragma once
#include "../common.h"
#include "elf.h"
#include "elf_symbols.h"
#include <string_view>
#include <sys/mman.h>

class Elf;
struct ElfSection;

/**
 * The owning data-structure that all debug info symbols point to. The ObjFile is meant
 * to outlive them all, so it's safe to take raw pointers into `loaded_binary`.
 */

// TODO(simon): Make `ObjectFile` the owner of Minimal Symbols and parsed debug information, for instance the
// std::map in target that contains minimal symbols etc, so that we can effectively track life time and if for
// instance a shared library gets unloaded, we can kill the symbols along with it.

struct ObjectFile
{
  Path path;
  u64 size;
  const u8 *loaded_binary;
  TPtr<void> entry_point;
  TPtr<void> vm_text_section;
  Elf *parsed_elf = nullptr;
  std::unordered_map<std::string_view, MinSymbol> minimal_symbols;

  ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept;
  ~ObjectFile() noexcept;

  template <typename T>
  T *
  get_at_offset(u64 offset)
  {
    return (T *)(loaded_binary + offset);
  }

  template <typename T>
  T *
  get_at(u8 *ptr)
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
  TPtr<void> text_section_offset() const noexcept;
  std::optional<MinSymbol> get_minsymbol(std::string_view name) noexcept;
};

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
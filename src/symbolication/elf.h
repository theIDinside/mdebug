#pragma once
#include "../common.h"
#include <string_view>

#include <elf.h>
#include <unordered_map>

constexpr static u8 ELF_MAGIC[4]{0x7F, 0x45, 0x4C, 0x46};
constexpr static u8 ELF_MAGIC_[4]{EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3};
using Elf64Header = Elf64_Ehdr;
struct ObjectFile;

struct ElfSection
{
  u8 *m_section_ptr;
  const char *m_name;
  u64 m_section_size;
  u64 file_offset;
  TPtr<void> address;
  std::string_view get_name() const noexcept;
  u8 *begin() const noexcept;
  u8 *end() const noexcept;

  /**
   * Determines offset of `inside_ptr` from `m_section_ptr`.
   * Requires pointer to be >= m_section_ptr. This contract is only tested in debug builds.
   */
  u64 offset(u8 *inside_ptr) const noexcept;
  u64 size() const noexcept;
  const u8 *data() const noexcept;
};

struct ElfSectionData
{
  ElfSection *sections;
  u16 count;
};

class Elf
{
public:
  Elf(Elf64Header *header, ElfSectionData sections, ObjectFile *obj_file) noexcept;
  static void parse_objfile(ObjectFile *object_file) noexcept;
  std::span<ElfSection> sections() const noexcept;
  ElfSection *get_section(std::string_view name) const noexcept;
  ElfSection *get_section_or_panic(std::string_view name) const noexcept;

  /** Parses minimal symbols (from .symtab) and registers them with `obj_file` */
  void parse_min_symbols() const noexcept;

  Elf64Header *header;
  ElfSectionData m_sections;
  ObjectFile *obj_file;

  ElfSection *str_table;
  // Dwarf Sections, might as well keep direct pointers to them
  ElfSection *debug_info;
  ElfSection *debug_abbrev;
  ElfSection *debug_str;
  ElfSection *debug_line_str;
  ElfSection *debug_ranges;
  ElfSection *debug_line;
  ElfSection *debug_addr;
  ElfSection *debug_str_offsets;
  ElfSection *debug_rnglists;
  ElfSection *debug_loclist;
};

enum class DwarfSectionIdent : u8
{
#define SECTION(Ident, StringKey) Ident,
#include "../defs/elf.defs"
#undef SECTION
  COUNT
};

DwarfSectionIdent from_str(std::string_view str);
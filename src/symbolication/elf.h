#pragma once
#include "utils/macros.h"
#include <common.h>
#include <elf.h>
#include <string_view>
#include <typedefs.h>

constexpr static u8 ELF_MAGIC[4]{0x7F, 0x45, 0x4C, 0x46};
constexpr static u8 ELF_MAGIC_[4]{EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3};
using Elf64Header = Elf64_Ehdr;
class ObjectFile;

enum class ElfSec : u8
{
#define SECTION(Ident, StringKey) Ident,
#include "../defs/elf.defs"
#undef SECTION
  COUNT
};

ElfSec from_str(std::string_view str);

std::optional<ElfSec> to_identifier(std::string_view str);

constexpr std::string_view
sec_name(ElfSec ident) noexcept
{
  using enum ElfSec;
#define SECTION(Ident, Name)                                                                                      \
  case Ident:                                                                                                     \
    return #Name;
  switch (ident) {
#include "../defs/elf.defs"
#undef SECTION
  case ElfSec::COUNT:
    return "ERROR_SECTION";
    break;
  }
  NEVER("Unknown elf section identifier");
}

struct ElfSection
{
  u8 *m_section_ptr;
  const char *m_name;
  u64 m_section_size;
  u64 file_offset;
  AddrPtr address;
  // TODO(simon): add relocated_address field
  std::string_view get_name() const noexcept;
  const u8 *begin() const noexcept;
  const u8 *end() const noexcept;
  const u8 *into(AddrPtr addr) const noexcept;

  /**
   * Determines offset of `inside_ptr` from `m_section_ptr`.
   * Requires pointer to be >= m_section_ptr. This contract is only tested in debug builds.
   */
  u64 get_ptr_offset(const u8 *inside_ptr) const noexcept;

  const u8 *offset(u64 offset) const noexcept;
  u64 remaining_bytes(const u8 *ptr) const noexcept;
  u64 size() const noexcept;
};

struct ElfSectionData
{
  ElfSection *sections;
  u16 count;
};

class Elf
{
public:
  Elf(Elf64Header *header, ElfSectionData sections, ObjectFile &obj_file) noexcept;
  ~Elf() noexcept;
  std::span<ElfSection> sections() const noexcept;
  const ElfSection *get_section(std::string_view name) const noexcept;
  constexpr const ElfSection *get_section(ElfSec section) const noexcept;
  const ElfSection *get_section_or_panic(std::string_view name) const noexcept;
  bool has_dwarf() const noexcept;

  /** Parses minimal symbols (from .symtab) and registers them with `obj_file` */
  void parse_min_symbols() const noexcept;
  bool AddressesNeedsRelocation() const noexcept;

  Elf64Header *header;
  ElfSectionData m_sections;
  ObjectFile &obj_file;

  const ElfSection *str_table;
  // Dwarf Sections, might as well keep direct pointers to them
  const ElfSection *debug_info;
  const ElfSection *debug_abbrev;
  const ElfSection *debug_str;
  const ElfSection *debug_line_str;
  const ElfSection *debug_ranges;
  const ElfSection *debug_aranges;
  const ElfSection *debug_line;
  const ElfSection *debug_addr;
  const ElfSection *debug_str_offsets;
  const ElfSection *debug_rnglists;
  const ElfSection *debug_loclist;
};
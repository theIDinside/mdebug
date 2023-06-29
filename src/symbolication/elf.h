#pragma once
#include "../common.h"
#include <string_view>

#include <elf.h>
#include <unordered_map>

constexpr static u8 ELF_MAGIC[4]{0x7F, 0x45, 0x4C, 0x46};
constexpr static u8 ELF_MAGIC_[4]{EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3};
using Elf64Header = Elf64_Ehdr;
struct ObjectFile;
struct MinSymbol;

struct ElfSection
{
  u8 *m_section_ptr;
  const char *m_name;
  u64 m_section_size;
  u64 file_offset;
  std::string_view get_name() const noexcept;
};

struct ElfSectionData
{
  ElfSection *sections;
  u16 count;
};

class Elf
{
public:
  Elf(Elf64Header *header, ElfSectionData sections) noexcept;
  static Elf *parse_objfile(ObjectFile *object_file) noexcept;
  std::span<ElfSection> sections() const noexcept;

  std::unordered_map<u64, MinSymbol> parse_min_symbols() const noexcept;

  Elf64Header *header;
  ElfSectionData m_sections;
  ElfSection *str_table = nullptr;
};

enum class DwarfSectionIdent : u8
{
#define SECTION(Ident, StringKey) Ident,
#include "../defs/elf.defs"
#undef SECTION
  COUNT
};

DwarfSectionIdent from_str(std::string_view str);
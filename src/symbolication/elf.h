#pragma once
#include <string_view>
#include "../common.h"
#include <elf.h>

constexpr static u8 ELF_MAGIC[4]{0x7F, 0x45, 0x4C, 0x46};
constexpr static u8 ELF_MAGIC_[4]{EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3};
using Elf64Header = Elf64_Ehdr;
struct ObjectFile;

struct ElfSection {
  u8 *m_section_ptr;
  const char *m_name;
  u64 m_section_size;
  std::string_view get_name() const noexcept;
};

struct ElfSectionData {
  ElfSection* sections;
  u16 count;
};

class Elf {
public:
  Elf(Elf64Header* header, ElfSectionData sections) noexcept;
  static Elf parse_objfile(ObjectFile* object_file) noexcept;

  std::span<ElfSection> sections() const noexcept;

  Elf64Header *header;
  ElfSectionData m_sections;
};

enum class DwarfSectionIdent : u8 {
  #define SECTION(Ident, StringKey) Ident,
  #include "../defs/elf.defs"
  #undef SECTION
  COUNT
};

DwarfSectionIdent from_str(std::string_view str);
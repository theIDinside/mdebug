#include "elf.h"
#include <bits/ranges_util.h>
#include <cstdint>
#include <elf.h>
#include "objfile.h"
#include "elf_symbols.h"
#include <ranges>
#include <algorithm>

std::string_view
ElfSection::get_name() const noexcept
{
  return m_name;
}

DwarfSectionIdent
from_str(std::string_view str)
{
#define SECTION(Ident, StringKey)                                                                                 \
  if (str == StringKey)                                                                                           \
    return DwarfSectionIdent::Ident;                                                                              \
  else
#undef SECTION
  PANIC(fmt::format("Failed to parse section name {}", str))
}

Elf::Elf(Elf64Header *header, ElfSectionData sections) noexcept : header(header), m_sections(sections) {}

std::span<ElfSection> Elf::sections() const noexcept {
  return std::span<ElfSection>{m_sections.sections, m_sections.sections+m_sections.count};
}

Elf*
Elf::parse_objfile(ObjectFile *object_file) noexcept
{
  const auto header = object_file->get_at<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  ElfSectionData data = {.sections = new ElfSection[header->e_shnum], .count = header->e_shnum};
  const auto sec_names_offset_hdr = object_file->get_at<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));
  ElfSection* str_table = nullptr;

  auto sec_hdrs_offset = header->e_shoff;
  for (auto i = 0; i < data.count; i++) {
    const auto sec_hdr = object_file->get_at<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    data.sections[i].m_section_ptr = object_file->get_at<u8>(sec_hdr->sh_offset);
    data.sections[i].m_section_size = sec_hdr->sh_size;
    data.sections[i].m_name = object_file->get_at<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name);
    data.sections[i].file_offset = sec_hdr->sh_offset;
    if(data.sections[i].get_name() == ".strtab") {
      str_table = &data.sections[i];
    }
  }

  auto elf = new Elf{header, data};
  elf->str_table = str_table;
  return elf;
}

std::unordered_map<u64, MinSymbol> Elf::parse_min_symbols() const noexcept {
  std::unordered_map<u64, MinSymbol> result;

  std::span<ElfSection> sects = sections();
  auto strtable = std::ranges::find_if(sects, [](ElfSection& sect) {
    return sect.get_name() == ".strtab";
  });

  ASSERT(strtable != std::end(sects), "Could not find section .strtab");

  for(auto& sec : sections()) {
    if(sec.get_name() == ".symtab") {
      auto start = sec.m_section_ptr;
      auto end = start + sec.m_section_size;
      auto entries = (end - start) / sizeof(Elf64_Sym);
      std::span<Elf64_Sym> symbols{(Elf64_Sym*)sec.m_section_ptr, entries};
      auto hasher = std::hash<std::string_view>{};
      for(auto& symbol : symbols) {
        std::string_view name{(const char*)str_table->m_section_ptr+symbol.st_name};
        u64 hashkey = hasher(name);
        result[hashkey] = MinSymbol{.name = name, .address = symbol.st_value};
      }
    }
  }
  return result;
}
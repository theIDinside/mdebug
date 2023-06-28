#include "elf.h"
#include <cstdint>
#include <elf.h>
#include "objfile.h"

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

Elf
Elf::parse_objfile(ObjectFile *object_file) noexcept
{
  const auto header = object_file->get_at<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  ElfSectionData data = {.sections = new ElfSection[header->e_shnum], .count = header->e_shnum};
  const auto sec_names_offset_hdr = object_file->get_at<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));

  auto sec_hdrs_offset = header->e_shoff;
  for (auto i = 0; i < data.count; i++) {
    const auto sec_hdr = object_file->get_at<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    data.sections[i].m_section_ptr = object_file->get_at<u8>(sec_hdr->sh_offset);
    data.sections[i].m_section_size = sec_hdr->sh_size;
    data.sections[i].m_name = object_file->get_at<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name);
  }

  return Elf{header, data};
}
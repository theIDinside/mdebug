#include "elf.h"
#include "elf_symbols.h"
#include "objfile.h"
#include <algorithm>
#include <bits/ranges_util.h>
#include <cstdint>
#include <elf.h>
#include <ranges>

std::string_view
ElfSection::get_name() const noexcept
{
  return m_name;
}

const u8 *
ElfSection::begin() const noexcept
{
  return m_section_ptr;
}

const u8 *
ElfSection::end() const noexcept
{
  return m_section_ptr + m_section_size;
}

const u8 *
ElfSection::into(AddrPtr vm_addr) const noexcept
{
  ASSERT(vm_addr >= address, "Virtual Memory address {} is < {}", vm_addr, address);
  ASSERT((vm_addr - address) < size(), "Virtual memory address {} is > {}", vm_addr, address + size());
  const AddrPtr offset = (vm_addr - address);
  return begin() + offset.get();
}

bool
ElfSection::contains_relo_addr(AddrPtr vm_address) const noexcept
{
  if (vm_address < this->address)
    return false;
  return (vm_address - address) < size();
}

u64
ElfSection::offset(const u8 *inside_ptr) const noexcept
{
  ASSERT(inside_ptr >= m_section_ptr, "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})",
         (void *)inside_ptr, (void *)m_section_ptr);
  return (inside_ptr - m_section_ptr);
}

u64
ElfSection::size() const noexcept
{
  return m_section_size;
}

const u8 *
ElfSection::data() const noexcept
{
  return m_section_ptr;
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

Elf::Elf(Elf64Header *header, ElfSectionData sections, ObjectFile *obj_file) noexcept
    : header(header), m_sections(sections), obj_file(obj_file), str_table{nullptr}, debug_info{nullptr},
      debug_abbrev{nullptr}, debug_str{nullptr}, debug_ranges{nullptr}, debug_line{nullptr}, debug_addr{nullptr},
      debug_str_offsets{nullptr}, debug_rnglists{nullptr}, debug_loclist{nullptr}
{
  obj_file->parsed_elf = this;
  str_table = get_section_or_panic(".strtab");
  debug_info = get_section_or_panic(".debug_info");
  debug_abbrev = get_section_or_panic(".debug_abbrev");
  debug_str = get_section(".debug_str");
  debug_line = get_section(".debug_line");
  debug_ranges = get_section(".debug_ranges");
  debug_line_str = get_section(".debug_line_str");
}

std::span<ElfSection>
Elf::sections() const noexcept
{
  return std::span<ElfSection>{m_sections.sections, m_sections.sections + m_sections.count};
}

ElfSection *
Elf::get_section(std::string_view name) const noexcept
{
  for (auto &sec : sections()) {
    if (sec.get_name() == name) {
      return &sec;
    }
  }
  return nullptr;
}

ElfSection *
Elf::get_section_or_panic(std::string_view name) const noexcept
{
  auto sec = get_section(name);
  ASSERT(sec != nullptr, "Expected {} not to be null", name);
  return sec;
}

void
Elf::parse_objfile(ObjectFile *object_file) noexcept
{
  const auto header = object_file->get_at_offset<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  ElfSectionData data = {.sections = new ElfSection[header->e_shnum], .count = header->e_shnum};
  const auto sec_names_offset_hdr =
      object_file->get_at_offset<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));

  auto sec_hdrs_offset = header->e_shoff;
  for (auto i = 0; i < data.count; i++) {
    const auto sec_hdr = object_file->get_at_offset<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    data.sections[i].m_section_ptr = object_file->get_at_offset<u8>(sec_hdr->sh_offset);
    data.sections[i].m_section_size = sec_hdr->sh_size;
    data.sections[i].m_name =
        object_file->get_at_offset<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name);
    data.sections[i].file_offset = sec_hdr->sh_offset;
    data.sections[i].address = sec_hdr->sh_addr;
  }
  // ObjectFile is the owner of `Elf`
  new Elf{header, data, object_file};
}

void
Elf::parse_min_symbols() const noexcept
{

  std::span<ElfSection> sects = sections();
  auto strtable = std::ranges::find_if(sects, [](ElfSection &sect) { return sect.get_name() == ".strtab"; });

  ASSERT(strtable != std::end(sects), "Could not find section .strtab");

  for (auto &sec : sections()) {
    if (sec.get_name() == ".symtab") {
      auto start = sec.m_section_ptr;
      auto end = start + sec.m_section_size;
      auto entries = (end - start) / sizeof(Elf64_Sym);
      std::span<Elf64_Sym> symbols{(Elf64_Sym *)sec.m_section_ptr, entries};
      for (auto &symbol : symbols) {
        std::string_view name{(const char *)str_table->m_section_ptr + symbol.st_name};
        obj_file->minimal_symbols[name] =
            MinSymbol{.name = name, .address = symbol.st_value, .maybe_size = symbol.st_size};
      }
    }
  }
}
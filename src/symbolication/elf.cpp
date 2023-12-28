#include "elf.h"
#include "elf_symbols.h"
#include "objfile.h"
#include "symbolication/addr_sorter.h"
#include "utils/enumerator.h"

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

u64
ElfSection::get_ptr_offset(const u8 *inside_ptr) const noexcept
{
  ASSERT(inside_ptr >= m_section_ptr, "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})",
         (void *)inside_ptr, (void *)m_section_ptr);
  return (inside_ptr - m_section_ptr);
}

const u8 *
ElfSection::offset(u64 offset) const noexcept
{
  ASSERT(offset < m_section_size, "Offset {} is outside of section of size {}", offset, m_section_size);
  return m_section_ptr + offset;
}

u64
ElfSection::remaining_bytes(const u8 *ptr) const noexcept
{
  ASSERT(ptr >= m_section_ptr, "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})", (void *)ptr,
         (void *)m_section_ptr);
  const auto offset_bytes = get_ptr_offset(ptr);
  return size() - offset_bytes;
}

u64
ElfSection::size() const noexcept
{
  return m_section_size;
}

ElfSec
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
    : reloc(nullptr), header(header), m_sections(sections), obj_file(obj_file), str_table{nullptr},
      debug_info{nullptr}, debug_abbrev{nullptr}, debug_str{nullptr}, debug_ranges{nullptr},
      debug_aranges{nullptr}, debug_line{nullptr}, debug_addr{nullptr}, debug_str_offsets{nullptr},
      debug_rnglists{nullptr}, debug_loclist{nullptr}
{
  obj_file->parsed_elf = this;
  str_table = get_section(ElfSec::StringTable);
  debug_info = get_section(ElfSec::DebugInfo);
  debug_abbrev = get_section(ElfSec::DebugAbbrev);
  debug_str = get_section(ElfSec::DebugStr);
  debug_line = get_section(ElfSec::DebugLine);
  debug_ranges = get_section(ElfSec::DebugRanges);
  debug_line_str = get_section(ElfSec::DebugLineStr);
  debug_str_offsets = get_section(ElfSec::DebugStrOffsets);
  debug_rnglists = get_section(ElfSec::DebugRngLists);
  debug_loclist = get_section(ElfSec::DebugLocLists);
  debug_aranges = get_section(ElfSec::DebugAranges);
}

std::span<ElfSection>
Elf::sections() const noexcept
{
  return std::span<ElfSection>{m_sections.sections, m_sections.sections + m_sections.count};
}

constexpr const ElfSection *
Elf::get_section(ElfSec section) const noexcept
{
  return get_section(sec_name(section));
}

const ElfSection *
Elf::get_section(std::string_view name) const noexcept
{
  for (auto &sec : sections()) {
    if (sec.get_name() == name) {
      return &sec;
    }
  }
  return nullptr;
}

const ElfSection *
Elf::get_section_or_panic(std::string_view name) const noexcept
{
  auto sec = get_section(name);
  ASSERT(sec != nullptr, "Expected {} not to be null in {}", name, this->obj_file->path.c_str());
  return sec;
}

void
Elf::parse_elf_owned_by_obj(ObjectFile *object_file, AddrPtr reloc_base) noexcept
{
  DLOG("mdb", "Parsing objfile {}", object_file->path.c_str());
  const auto header = object_file->get_at_offset<Elf64Header>(0);
  ASSERT(std::memcmp(ELF_MAGIC, header->e_ident, 4) == 0, "ELF Magic not correct, expected {} got {}",
         *(u32 *)(ELF_MAGIC), *(u32 *)(header->e_ident));
  ElfSectionData data = {.sections = new ElfSection[header->e_shnum], .count = header->e_shnum};
  const auto sec_names_offset_hdr =
      object_file->get_at_offset<Elf64_Shdr>(header->e_shoff + (header->e_shstrndx * header->e_shentsize));

  auto min = UINTMAX_MAX;
  auto max = reloc_base.get();

  // good enough heuristic to determine mapped in ranges.
  for (auto i = 0; i < header->e_phnum; ++i) {
    auto phdr = object_file->get_at_offset<Elf64_Phdr>(header->e_phoff + header->e_phentsize * i);
    if (phdr->p_type == PT_LOAD) {
      min = std::min(phdr->p_vaddr + reloc_base, min);
      const auto end = phdr->p_vaddr + reloc_base + phdr->p_memsz;
      const auto align_adjust = phdr->p_align - (end % phdr->p_align);
      max = std::max(end + align_adjust, max);
    }
  }

  object_file->address_bounds = AddressRange{.low = min, .high = max};
  auto sec_hdrs_offset = header->e_shoff;
  // parse sections
  for (auto i = 0; i < data.count; i++) {
    const auto sec_hdr = object_file->get_at_offset<Elf64_Shdr>(sec_hdrs_offset);
    sec_hdrs_offset += header->e_shentsize;
    data.sections[i].m_section_ptr = object_file->get_at_offset<u8>(sec_hdr->sh_offset);
    data.sections[i].m_section_size = sec_hdr->sh_size;
    data.sections[i].m_name =
        object_file->get_at_offset<const char>(sec_names_offset_hdr->sh_offset + sec_hdr->sh_name);
    data.sections[i].file_offset = sec_hdr->sh_offset;
    data.sections[i].address = sec_hdr->sh_addr;
    data.sections[i].reloc_base = reloc_base;
  }
  // ObjectFile is the owner of `Elf`
  auto elf = new Elf{header, data, object_file};
  elf->set_relocation(reloc_base);
}

void
Elf::parse_min_symbols(AddrPtr base_vma) const noexcept
{
  if (auto strtab = get_section(ElfSec::StringTable); !strtab) {
    obj_file->has_elf_symbols = false;
    return;
  }
  DLOG("mdb", "{} min symbols, base_vma={}", obj_file->path.c_str(), base_vma);

  std::vector<MinSymbol> elf_fn_symbols{};
  std::unordered_map<std::string_view, MinSymbol> elf_object_symbols{};

  if (const auto sec = get_section(ElfSec::SymbolTable); sec) {
    auto start = sec->m_section_ptr;
    auto end = start + sec->m_section_size;
    auto entries = (end - start) / sizeof(Elf64_Sym);
    std::span<Elf64_Sym> symbols{(Elf64_Sym *)sec->m_section_ptr, entries};
    for (auto &symbol : symbols) {
      if (ELF64_ST_TYPE(symbol.st_info) == STT_FUNC) {
        std::string_view name{(const char *)str_table->m_section_ptr + symbol.st_name};
        const auto res =
            MinSymbol{.name = name, .address = base_vma + symbol.st_value, .maybe_size = symbol.st_size};
        elf_fn_symbols.push_back(res);
      } else if (ELF64_ST_TYPE(symbol.st_info) == STT_OBJECT) {
        std::string_view name{(const char *)str_table->m_section_ptr + symbol.st_name};
        elf_object_symbols[name] =
            MinSymbol{.name = name, .address = base_vma + symbol.st_value, .maybe_size = symbol.st_size};
      }
    }
    // TODO(simon): Again; sorting after insertion may not be as good as actually sorting while inserting.
    std::sort(elf_fn_symbols.begin(), elf_fn_symbols.end(), SortLowPc<MinSymbol>());
    obj_file->add_elf_symbols(std::move(elf_fn_symbols), std::move(elf_object_symbols));
  } else {
    LOG("mdb", "[warning]: No .symtab for {}", obj_file->path.c_str());
  }
}

void
Elf::set_relocation(AddrPtr vma) noexcept
{
  reloc = vma;
}

AddrPtr
Elf::relocate_addr(AddrPtr addr) noexcept
{
  return addr + reloc;
}

AddrPtr
Elf::obj_addr(AddrPtr addr) noexcept
{
  ASSERT(addr > reloc, "Address {} is below reloc base {}", addr, reloc);
  return addr - reloc;
}
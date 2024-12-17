#include "elf.h"
#include "elf_symbols.h"
#include "objfile.h"
#include <algorithm>

std::string_view
ElfSection::GetName() const noexcept
{
  return mName;
}

const u8 *
ElfSection::begin() const noexcept
{
  return mSectionData->data();
}

const u8 *
ElfSection::end() const noexcept
{
  return mSectionData->data() + mSectionData->size();
}

const u8 *
ElfSection::Into(AddrPtr vm_addr) const noexcept
{
  ASSERT(vm_addr >= address, "Virtual Memory address {} is < {}", vm_addr, address);
  ASSERT((vm_addr - address) < Size(), "Virtual memory address {} is > {}", vm_addr, address + Size());
  const AddrPtr offset = (vm_addr - address);
  return begin() + offset.get();
}

std::string_view ElfSection::GetNullTerminatedStringAt(u64 offset) const noexcept
{
  return std::string_view{(const char*)mSectionData->data() + offset};
}

u64
ElfSection::GetPointerOffset(const u8 *inside_ptr) const noexcept
{
  ASSERT(inside_ptr >= mSectionData->data(), "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})",
         (void *)inside_ptr, (void *)mSectionData->data());
  return (inside_ptr - mSectionData->data());
}

const u8 *
ElfSection::GetPointer(u64 offset) const noexcept
{
  ASSERT(offset < mSectionData->size_bytes(), "Offset {} is outside of section of size {}", offset,
         mSectionData->size_bytes());
  return mSectionData->data() + offset;
}

u64
ElfSection::RemainingBytes(const u8 *ptr) const noexcept
{
  ASSERT(ptr >= mSectionData->data(), "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})", (void *)ptr,
         (void *)mSectionData->data());
  const auto offset_bytes = GetPointerOffset(ptr);
  return Size() - offset_bytes;
}

u64
ElfSection::Size() const noexcept
{
  return mSectionData->size();
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

Elf::Elf(Elf64Header *header, std::vector<ElfSection> &&sections) noexcept
    : header(header), mSections(std::move(sections)), str_table{nullptr}, debug_info{nullptr},
      debug_abbrev{nullptr}, debug_str{nullptr}, debug_ranges{nullptr}, debug_aranges{nullptr},
      debug_line{nullptr}, debug_addr{nullptr}, debug_str_offsets{nullptr}, debug_rnglists{nullptr},
      debug_loclist{nullptr}
{
  str_table = GetSection(ElfSec::StringTable);
  debug_info = GetSection(ElfSec::DebugInfo);
  debug_abbrev = GetSection(ElfSec::DebugAbbrev);
  debug_str = GetSection(ElfSec::DebugStr);
  debug_line = GetSection(ElfSec::DebugLine);
  debug_addr = GetSection(ElfSec::DebugAddr);
  debug_ranges = GetSection(ElfSec::DebugRanges);
  debug_line_str = GetSection(ElfSec::DebugLineStr);
  debug_str_offsets = GetSection(ElfSec::DebugStrOffsets);
  debug_rnglists = GetSection(ElfSec::DebugRngLists);
  debug_loclist = GetSection(ElfSec::DebugLocLists);
  debug_aranges = GetSection(ElfSec::DebugAranges);
}

std::span<const ElfSection>
Elf::GetSections() const noexcept
{
  return mSections;
}

constexpr const ElfSection *
Elf::GetSection(ElfSec section) const noexcept
{
  return GetSection(SectionName(section));
}

const ElfSection *
Elf::GetSection(std::string_view name) const noexcept
{
  for (auto &sec : GetSections()) {
    if (sec.mName == name) {
      return &sec;
    }
  }
  return nullptr;
}

const ElfSection *
Elf::GetSectionInfallible(std::string_view name) const noexcept
{
  auto sec = GetSection(name);
  ASSERT(sec != nullptr, "Expected {} not to be null in object file!", name);
  return sec;
}

bool
Elf::HasDWARF() const noexcept
{
  return debug_info != nullptr;
}

bool
Elf::AddressesNeedsRelocation() const noexcept
{
  return header->e_type == ET_DYN;
}

/* static */
void
Elf::ParseMinimalSymbol(Elf* elf, ObjectFile& objectFile) noexcept
{
  if (auto strtab = elf->GetSection(ElfSec::StringTable); !strtab) {
    return;
  }

  std::vector<MinSymbol> elf_fn_symbols{};
  std::unordered_map<std::string_view, MinSymbol> elf_object_symbols{};

  if (const auto sec = elf->GetSection(ElfSec::SymbolTable); sec) {
    auto symbols = sec->GetDataAs<Elf64_Sym>();
    for (auto &symbol : symbols) {
      if (ELF64_ST_TYPE(symbol.st_info) == STT_FUNC) {
        std::string_view name = elf->str_table->GetNullTerminatedStringAt(symbol.st_name);
        const auto res = MinSymbol{.name = name, .address = symbol.st_value, .maybe_size = symbol.st_size};
        elf_fn_symbols.push_back(res);
      } else if (ELF64_ST_TYPE(symbol.st_info) == STT_OBJECT) {
        std::string_view name = elf->str_table->GetNullTerminatedStringAt(symbol.st_name);
        elf_object_symbols[name] =
          MinSymbol{.name = name, .address = symbol.st_value, .maybe_size = symbol.st_size};
      }
    }
    // TODO(simon): Again; sorting after insertion may not be as good as actually sorting while inserting.
    const auto cmp = [](const auto &a, const auto &b) -> bool { return a.address < b.address; };
    std::sort(elf_fn_symbols.begin(), elf_fn_symbols.end(), cmp);
    objectFile.AddMinimalElfSymbols(std::move(elf_fn_symbols), std::move(elf_object_symbols));
  } else {
    LOG(core, "[warning]: No .symtab for {}", objectFile.GetPathString());
  }
}
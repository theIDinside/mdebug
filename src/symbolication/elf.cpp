/** LICENSE TEMPLATE */
#include "elf.h"
#include "elf_symbols.h"
#include "objfile.h"
#include <algorithm>

namespace mdb {

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
ElfSection::Into(AddrPtr virtualMemoryAddress) const noexcept
{
  MDB_ASSERT(virtualMemoryAddress >= address, "Virtual Memory address {} is < {}", virtualMemoryAddress, address);
  MDB_ASSERT((virtualMemoryAddress - address) < Size(),
    "Virtual memory address {} is > {}",
    virtualMemoryAddress,
    address + Size());
  const AddrPtr offset = (virtualMemoryAddress - address);
  return begin() + offset.GetRaw();
}

const char *
ElfSection::GetCString(u64 offset) const noexcept
{
  return (const char *)mSectionData->data() + offset;
}

u64
ElfSection::GetPointerOffset(const u8 *insideRangePointer) const noexcept
{
  MDB_ASSERT(insideRangePointer >= mSectionData->data(),
    "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})",
    (void *)insideRangePointer,
    (void *)mSectionData->data());
  return (insideRangePointer - mSectionData->data());
}

const u8 *
ElfSection::GetPointer(u64 offset) const noexcept
{
  MDB_ASSERT(offset < mSectionData->size_bytes(),
    "Offset {} is outside of section of size {}",
    offset,
    mSectionData->size_bytes());
  return mSectionData->data() + offset;
}

u64
ElfSection::RemainingBytes(const u8 *ptr) const noexcept
{
  MDB_ASSERT(ptr >= mSectionData->data(),
    "parameter `inside_ptr` ({:p}) not >= section pointer ({:p})",
    (void *)ptr,
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
  PANIC(std::format("Failed to parse section name {}", str))
}

Elf::Elf(Elf64Header *header, std::vector<ElfSection> &&sections) noexcept
    : mElfHeader(header), mSections(std::move(sections)), mStrTable{ nullptr }, mDebugInfo{ nullptr },
      mDebugAbbrev{ nullptr }, mDebugStr{ nullptr }, mDebugRanges{ nullptr }, mDebugAranges{ nullptr },
      mDebugLine{ nullptr }, mDebugAddr{ nullptr }, mDebugStrOffsets{ nullptr }, mDebugRnglists{ nullptr },
      mDebugLoclist{ nullptr }
{
  mStrTable = GetSection(ElfSec::StringTable);
  mDynStrTable = GetSection(ElfSec::DynamicStringTable);
  mDebugInfo = GetSection(ElfSec::DebugInfo);
  mDebugAbbrev = GetSection(ElfSec::DebugAbbrev);
  mDebugStr = GetSection(ElfSec::DebugStr);
  mDebugLine = GetSection(ElfSec::DebugLine);
  mDebugAddr = GetSection(ElfSec::DebugAddr);
  mDebugRanges = GetSection(ElfSec::DebugRanges);
  mDebugLineStr = GetSection(ElfSec::DebugLineStr);
  mDebugStrOffsets = GetSection(ElfSec::DebugStrOffsets);
  mDebugRnglists = GetSection(ElfSec::DebugRngLists);
  mDebugLoclist = GetSection(ElfSec::DebugLocLists);
  if (!mDebugLoclist) {
    mDebugLoclist = GetSection(ElfSec::DebugLoc);
  }
  mDebugAranges = GetSection(ElfSec::DebugAranges);
}

std::span<const ElfSection>
Elf::GetSections() const noexcept
{
  return mSections;
}

static constexpr std::string_view
SectionName(ElfSec ident) noexcept
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
  MDB_ASSERT(sec != nullptr, "Expected {} not to be null in object file!", name);
  return sec;
}

bool
Elf::HasDWARF() const noexcept
{
  return mDebugInfo != nullptr;
}

bool
Elf::AddressesNeedsRelocation() const noexcept
{
  return mElfHeader->e_type == ET_DYN;
}

} // namespace mdb
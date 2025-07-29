/** LICENSE TEMPLATE */
#pragma once
#include "tracee_pointer.h"
#include "utils/immutable.h"
#include "utils/macros.h"
#include <common.h>
#include <elf.h>
#include <span>
#include <string_view>
#include <typedefs.h>

namespace mdb {
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

struct ElfSection
{
  Immutable<std::span<const u8>> mSectionData;
  Immutable<std::string_view> mName;
  Immutable<u64> file_offset;
  Immutable<AddrPtr> address;
  // TODO(simon): add relocated_address field
  std::string_view GetName() const noexcept;
  // Have to be non-capitalized to play with std algos
  const u8 *begin() const noexcept;
  const u8 *end() const noexcept;
  const u8 *Into(AddrPtr addr) const noexcept;
  const char *GetCString(u64 offset) const noexcept;

  /**
   * Determines offset of `inside_ptr` from `m_section_ptr`.
   * Requires pointer to be >= m_section_ptr. This contract is only tested in debug builds.
   */
  u64 GetPointerOffset(const u8 *inside_ptr) const noexcept;

  const u8 *GetPointer(u64 offset) const noexcept;
  u64 RemainingBytes(const u8 *ptr) const noexcept;
  u64 Size() const noexcept;

  template <typename T>
  auto
  GetDataAs() const noexcept -> std::span<const T>
  {
    ASSERT(mSectionData->size_bytes() % sizeof(T) == 0, "data is unaligned!");
    const T *ptr = reinterpret_cast<const T *>(mSectionData->data());
    return std::span<const T>{ptr, mSectionData->size_bytes() / sizeof(T)};
  }

  template <typename T>
  const T *
  GetDataAsIfAligned(u64 offset) const noexcept
  {
    if (IsAligned<T>((void *)(mSectionData->data() + offset))) {
      return (const T *)(mSectionData->data() + offset);
    }
    return nullptr;
  }
};

struct ElfSectionData
{
  ElfSection *sections;
  u16 count;
};

class Elf
{
public:
  Elf(Elf64Header *header, std::vector<ElfSection> &&sections) noexcept;
  std::span<const ElfSection> GetSections() const noexcept;
  const ElfSection *GetSection(std::string_view name) const noexcept;
  constexpr const ElfSection *GetSection(ElfSec section) const noexcept;
  const ElfSection *GetSectionInfallible(std::string_view name) const noexcept;
  bool HasDWARF() const noexcept;

  /** Parses minimal symbols (from .symtab) and registers them with `obj_file` */
  static void ParseMinimalSymbol(Elf *elf, ObjectFile &objectFile) noexcept;
  bool AddressesNeedsRelocation() const noexcept;

  Elf64Header *mElfHeader;
  Immutable<std::vector<ElfSection>> mSections;

  const ElfSection *mStrTable;
  // Dwarf Sections, might as well keep direct pointers to them
  const ElfSection *mDebugInfo;
  const ElfSection *mDebugAbbrev;
  const ElfSection *mDebugStr;
  const ElfSection *mDebugLineStr;
  const ElfSection *mDebugRanges;
  const ElfSection *mDebugAranges;
  const ElfSection *mDebugLine;
  const ElfSection *mDebugAddr;
  const ElfSection *mDebugStrOffsets;
  const ElfSection *mDebugRnglists;
  const ElfSection *mDebugLoclist;
};
} // namespace mdb
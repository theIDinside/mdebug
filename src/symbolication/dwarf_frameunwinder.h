#pragma once
#include "../common.h"
#include "dwarf_defs.h"

struct ElfSection;
struct ObjectFile;

namespace sym {

struct ByteCodeInterpreter
{
  ByteCodeInterpreter(std::span<const u8> stream) noexcept;
  std::vector<DwarfCallFrame> debug_parse();

  void advance_loc(u64 delta) noexcept;

  std::span<const u8> byte_stream;
};

struct Enc
{
  DwarfExceptionHeaderApplication loc_fmt;
  DwarfExceptionHeaderEncoding value_fmt;
};

union QuadWord
{
  i64 i;
  u64 u;
};

struct EhFrameHeader
{
  u8 version;
  Enc frame_ptr_encoding;
  Enc fde_count_encoding;
  Enc table_encoding;
  QuadWord frame_ptr;
  QuadWord fde_count;
};

EhFrameHeader read_frame_header(DwarfBinaryReader &reader);

struct CommonInformationEntry
{
  u64 length;
  DwFormat fmt;
  Enc fde_encoding;
  u8 addr_size;
  u8 segment_size;
  u8 version;
  u64 id;
  std::optional<std::string_view> augmentation_string;
  AddrPtr personality_address;
  u64 code_alignment_factor;
  i64 data_alignment_factor;
  u64 retaddr_register;
  std::span<const u8> instructions;
};

CommonInformationEntry read_cie(DwarfBinaryReader &reader);

using CIE = CommonInformationEntry;

struct FrameDescriptionEntry
{
  u64 length;
  u64 cie_offset;
  u64 address_range;
  std::span<u8> instructions;
  u16 padding;
};
using FDE = FrameDescriptionEntry;

struct EhFrameEntry
{
  AddrPtr initial_location;
  FDE *fde;
};

/** Structure describing where to find unwind info */
struct UnwindInfo
{
  AddrPtr resume_address();

  AddrPtr start;
  AddrPtr end;
  u8 code_align;
  i8 data_align;
  u8 aug_data_len;
  CIE *cie;
  std::span<const u8> fde_insts{};
};

class Unwinder
{
public:
  Unwinder(ObjectFile *objfile) noexcept;
  u64 total_cies() const noexcept;
  u64 total_fdes() const noexcept;

  // Objfile
  ObjectFile *objfile;
  // .debug_frame
  std::vector<CIE> dwarf_debug_cies;
  std::vector<UnwindInfo> dwarf_unwind_infos;

  // .eh_frame
  std::vector<CIE> elf_eh_cies;
  std::vector<UnwindInfo> elf_eh_unwind_infos;
};

std::pair<u64, u64> elf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept;
std::pair<u64, u64> dwarf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept;
CommonInformationEntry read_cie(u64 length, DwarfBinaryReader &reader) noexcept;
Unwinder *parse_eh(ObjectFile *objfile, const ElfSection *eh_frame, int fde_count) noexcept;
void parse_dwarf_eh(Unwinder *unwinder_db, const ElfSection *debug_frame, int fde_count) noexcept;

FrameDescriptionEntry read_fde(DwarfBinaryReader &reader);

} // namespace sym
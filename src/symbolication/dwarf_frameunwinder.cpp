#include "dwarf_frameunwinder.h"
#include "dwarf_defs.h"
#include "elf.h"
#include "objfile.h"

namespace sym {

ByteCodeInterpreter::ByteCodeInterpreter(std::span<const u8> stream) noexcept : byte_stream(stream) {}

std::vector<DwarfCallFrame>
ByteCodeInterpreter::debug_parse()
{
  std::vector<DwarfCallFrame> debug;
  using I = DwarfCallFrame;
  DwarfBinaryReader reader{byte_stream.data(), byte_stream.size()};
  while (reader.has_more()) {
    auto op = reader.read_value<u8>();
    switch (op & 0b1100'0000) {
    case 0b0100'0000: {
      debug.push_back(I::DW_CFA_advance_loc);
      break;
    }
    case 0b1000'0000: {
      debug.push_back(I::DW_CFA_offset);
      const auto offset = reader.read_uleb128<u64>();
      break;
    }
    case 0b1100'0000:
      debug.push_back(I::DW_CFA_restore);
      break;
    default:
      switch (op) {
      case 0:
        debug.push_back(I::DW_CFA_nop);
        break;
      case 0x01: {
        debug.push_back(I::DW_CFA_set_loc);
        const auto addr = reader.read_value<u64>();
      } break;
      case 0x02: {
        debug.push_back(I::DW_CFA_advance_loc1);
        const auto delta = reader.read_value<u8>();
      } break;
      case 0x03: {
        debug.push_back(I::DW_CFA_advance_loc2);
        const auto delta = reader.read_value<u16>();
      } break;
      case 0x04: {
        debug.push_back(I::DW_CFA_advance_loc4);
        const auto delta = reader.read_value<u32>();
      } break;
      case 0x05: {
        debug.push_back(I::DW_CFA_offset_extended);
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
      } break;
      case 0x06: {
        debug.push_back(I::DW_CFA_restore_extended);
        const auto reg = reader.read_uleb128<u64>();
      } break;
      case 0x07: {
        debug.push_back(I::DW_CFA_undefined);
        const auto reg = reader.read_uleb128<u64>();
      } break;
      case 0x08: {
        debug.push_back(I::DW_CFA_same_value);
        const auto reg = reader.read_uleb128<u64>();
      } break;
      case 0x09: {
        debug.push_back(I::DW_CFA_register);
        const auto reg1 = reader.read_uleb128<u64>();
        const auto reg2 = reader.read_uleb128<u64>();
      } break;
      case 0x0a: {
        debug.push_back(I::DW_CFA_remember_state);
      } break;
      case 0x0b: {
        debug.push_back(I::DW_CFA_restore_state);
      } break;
      case 0x0c: {
        debug.push_back(I::DW_CFA_def_cfa);
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
      } break;
      case 0x0d: {
        debug.push_back(I::DW_CFA_def_cfa_register);
        const auto reg = reader.read_uleb128<u64>();
      } break;
      case 0x0e: {
        debug.push_back(I::DW_CFA_def_cfa_offset);
        const auto offset = reader.read_uleb128<u64>();
      } break;
      case 0x0f: {
        debug.push_back(I::DW_CFA_def_cfa_expression);
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
      } break;
      case 0x10: {
        debug.push_back(I::DW_CFA_expression);
        const auto reg = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
      } break;
      case 0x11: {
        debug.push_back(I::DW_CFA_offset_extended_sf);
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
      } break;
      case 0x12: {
        debug.push_back(I::DW_CFA_def_cfa_sf);
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
      } break;
      case 0x13: {
        debug.push_back(I::DW_CFA_def_cfa_offset_sf);
        const auto offset = reader.read_leb128<i64>();
      } break;
      case 0x14: {
        debug.push_back(I::DW_CFA_val_offset);
        const auto v1 = reader.read_uleb128<u64>();
        const auto v2 = reader.read_uleb128<u64>();
      } break;
      case 0x15: {
        debug.push_back(I::DW_CFA_val_offset_sf);
        const auto v1 = reader.read_uleb128<u64>();
        const auto v2 = reader.read_leb128<i64>();
      } break;
      case 0x16: {
        debug.push_back(I::DW_CFA_val_expression);
        const auto val = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
      } break;
      case 0x1c:
        TODO("DW_CFA_lo_user not supported");
      case 0x3f:
        TODO("DW_CFA_hi_user not supported");
      default:
        PANIC(fmt::format("Could not decode byte code: {:x} == {:b}", op, op));
      }
    }
  }
  return debug;
}

AddrPtr
UnwindInfo::resume_address()
{
  TODO("UnwindInfo::resume_address()");
}

constexpr auto
parse_encoding(u8 value)
{
  return Enc{.loc_fmt = (DwarfExceptionHeaderApplication)(0b1111'0000 & value),
             .value_fmt = (DwarfExceptionHeaderEncoding)(0b0000'1111 & value)};
}

static AddrPtr
iloc_uleb_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_uleb128<u64>();
}

static AddrPtr
iloc_u16_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<u16>();
}

static AddrPtr
iloc_u32_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<u32>();
}

static AddrPtr
iloc_u64_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<u64>();
}

static AddrPtr
iloc_i16_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<i16>();
}

static AddrPtr
iloc_i32_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<i32>();
}

static AddrPtr
iloc_i64_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_value<i64>();
}

static AddrPtr
iloc_ileb_reader(ElfSection *hdr, DwarfBinaryReader &reader)
{
  return hdr->address + reader.read_leb128<i64>();
}

static AddrPtr
iloc_uleb_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_uleb128<u64>();
}

static AddrPtr
iloc_u16_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_value<u16>();
}

static AddrPtr
iloc_u32_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{

  return reader.read_value<u32>();
}

static AddrPtr
iloc_u64_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_value<u64>();
}

static AddrPtr
iloc_i16_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_value<i16>();
}

static AddrPtr
iloc_i32_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_value<i32>();
}

static AddrPtr
iloc_i64_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_value<i64>();
}

static AddrPtr
iloc_ileb_reader_abs(ElfSection *, DwarfBinaryReader &reader)
{
  return reader.read_leb128<i64>();
}

using ExprOperation = AddrPtr (*)(ElfSection *, DwarfBinaryReader &);

constexpr QuadWord
read_value(DwarfExceptionHeaderEncoding encoding, DwarfBinaryReader &reader)
{
  switch (encoding) {
  case DwarfExceptionHeaderEncoding::DW_EH_PE_omit:
    return QuadWord{0};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_uleb128:
    return QuadWord{.u = reader.read_uleb128<u64>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata2:
    return QuadWord{.u = reader.read_value<u16>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata4:
    return QuadWord{.u = reader.read_value<u32>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata8:
    return QuadWord{.u = reader.read_value<u64>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sleb128:
    return QuadWord{.i = reader.read_leb128<i64>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata2:
    return QuadWord{.i = reader.read_value<i16>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata4:
    return QuadWord{.i = reader.read_value<i32>()};
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata8:
    return QuadWord{.i = reader.read_value<i64>()};
  }
}

EhFrameHeader
read_frame_header(DwarfBinaryReader &reader)
{
  EhFrameHeader header;
  header.version = reader.read_value<u8>();
  header.frame_ptr_encoding = parse_encoding(reader.read_value<u8>());
  header.fde_count_encoding = parse_encoding(reader.read_value<u8>());
  header.table_encoding = parse_encoding(reader.read_value<u8>());
  header.frame_ptr = read_value(header.frame_ptr_encoding.value_fmt, reader);
  header.fde_count = read_value(header.fde_count_encoding.value_fmt, reader);
  return header;
}

ExprOperation
get_reader(EhFrameHeader &header)
{
  ExprOperation reader;
  switch (header.table_encoding.value_fmt) {
  case DwarfExceptionHeaderEncoding::DW_EH_PE_omit:
  case DwarfExceptionHeaderEncoding::DW_EH_PE_uleb128:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_uleb_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_uleb_reader;
    } else {
      PANIC("Unsupported initial location format");
    }

    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata2:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_u16_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_u16_reader;
    } else {
      PANIC("Unsupported initial location format");
    }

    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata4:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_u32_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_u32_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_udata8:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_u64_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_u64_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sleb128:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_ileb_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_ileb_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata2:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_i16_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_i16_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata4:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_i32_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_i32_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  case DwarfExceptionHeaderEncoding::DW_EH_PE_sdata8:
    if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
      reader = &iloc_i64_reader_abs;
    } else if (header.table_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_datarel) {
      reader = &iloc_i64_reader;
    } else {
      PANIC("Unsupported initial location format");
    }
    break;
  }
  return reader;
}

std::pair<u64, u64>
elf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    auto id = reader.read_value<u32>();
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (len == 0)
      return {cie_count, fde_count};
    if (id == 0)
      ++cie_count;
    else
      ++fde_count;
    reader.skip(len - 4);
  }
  PANIC("We should see a terminator entry (ZERO ENTRY) before running out of bytes");
  return {cie_count, fde_count};
}

std::pair<u64, u64>
dwarf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    auto id = reader.read_value<u32>();
    // apparently .debug_frame does *not* have a 0-length entry as a terminator. Great. Amazing.
    if (len == 0)
      return {cie_count, fde_count};
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (id == 0xff'ff'ff'ff)
      ++cie_count;
    else
      ++fde_count;
    reader.skip(len - 4);
  }
  return {cie_count, fde_count};
}

Unwinder *
parse_eh(ObjFile *objfile, const ElfSection *eh_frame, int fde_count) noexcept
{
  DwarfBinaryReader reader{eh_frame->m_section_ptr, eh_frame->size()};
  auto unwinder_db = new Unwinder{objfile};

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = elf_eh_calculate_entries_count(DwarfBinaryReader{reader});
  unwinder_db->elf_eh_cies.reserve(cie_count);
  unwinder_db->elf_eh_unwind_infos.reserve(fdes_count);

  for (; fde_count != 0; --fde_count) {
    constexpr auto len_field_len = 4;
    const auto entry_length = reader.read_value<u32>();
    ASSERT(entry_length != 0xff'ff'ff'ff, "GCC and clang do not support 64-bit .eh_frame; so why should we?");
    const auto current_offset = reader.bytes_read();
    if (entry_length == 0) {
      return unwinder_db;
    }

    reader.bookmark();
    auto cie_ptr = reader.read_value<u32>();
    if (cie_ptr == 0) { // this is a CIE
      unwinder_db->elf_eh_cies.push_back(read_cie(entry_length, reader));
      cies[current_offset - len_field_len] = unwinder_db->elf_eh_cies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cie_ptr];
      auto &cie = unwinder_db->elf_eh_cies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      ASSERT(initial_loc < 0, "Expected initial loc to be negative offset");
      AddrPtr begin = (eh_frame->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      auto aug_data_length = 0;
      if (cie.augmentation_string->contains("z")) {
        aug_data_length = reader.read_uleb128<u64>();
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      DLOG("mdb", "Unwind Info for {} .. {}; CIE instruction count {}; FDE instruction count: {}", begin, end,
           cie.instructions.size(), ins.size());
      unwinder_db->elf_eh_unwind_infos.push_back(UnwindInfo{
          .start = begin,
          .end = end,
          .code_align = static_cast<u8>(cie.code_alignment_factor),
          .data_align = static_cast<i8>(cie.data_alignment_factor),
          .cie = &cie,
          .fde_insts = ins,
      });
    }
  }
  return unwinder_db;
}

void
parse_dwarf_eh(Unwinder *unwinder_db, const ElfSection *debug_frame, int fde_count) noexcept
{
  DwarfBinaryReader reader{debug_frame->m_section_ptr, debug_frame->size()};

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = dwarf_eh_calculate_entries_count(DwarfBinaryReader{reader});
  unwinder_db->dwarf_debug_cies.reserve(unwinder_db->elf_eh_cies.size() + cie_count);
  unwinder_db->dwarf_unwind_infos.reserve(unwinder_db->elf_eh_unwind_infos.size() + fdes_count);

  for (; fde_count != 0; --fde_count) {
    constexpr auto len_field_len = 4;
    const auto entry_length = reader.read_value<u32>();
    ASSERT(entry_length != 0xff'ff'ff'ff, "GCC and clang do not support 64-bit .eh_frame; so why should we?");
    const auto current_offset = reader.bytes_read();
    if (entry_length == 0) {
      return;
    }

    reader.bookmark();
    auto cie_ptr = reader.read_value<u32>();
    if (cie_ptr == 0xff'ff'ff'ff) { // this is a CIE
      unwinder_db->dwarf_debug_cies.push_back(read_cie(entry_length, reader));
      cies[current_offset - len_field_len] = unwinder_db->dwarf_debug_cies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cie_ptr];
      auto &cie = unwinder_db->dwarf_debug_cies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      ASSERT(initial_loc < 0, "Expected initial loc to be negative offset");
      AddrPtr begin = (debug_frame->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      auto aug_data_length = 0;
      const auto augstr = cie.augmentation_string.value_or("");
      if (augstr.contains("z")) {
        aug_data_length = reader.read_uleb128<u64>();
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      DLOG("mdb", "Unwind Info for {} .. {}; CIE instruction count {}; FDE instruction count: {}", begin, end,
           cie.instructions.size(), ins.size());
      unwinder_db->dwarf_unwind_infos.push_back(UnwindInfo{
          .start = begin,
          .end = end,
          .code_align = static_cast<u8>(cie.code_alignment_factor),
          .data_align = static_cast<i8>(cie.data_alignment_factor),
          .cie = &cie,
          .fde_insts = ins,
      });
    }
  }
}

CommonInformationEntry
read_cie(DwarfBinaryReader &reader)
{
  CIE cie;
  const auto [fmt, len] = reader.read_initial_length_additional<DwarfBinaryReader::InitLengthRead::Ignore>();
  DwarfBinaryReader entry_reader{reader.current_ptr(), len};
  cie.length = len;
  cie.fmt = fmt;
  if (fmt == DwFormat::DW32) {
    cie.id = entry_reader.read_value<u32>();
  } else {
    cie.id = entry_reader.read_value<u64>();
  }
  cie.version = entry_reader.read_value<u8>();

  const auto has_augment = entry_reader.peek_value<i8>();
  if ((bool)has_augment) {
    cie.augmentation_string = entry_reader.read_string();
    // this is a UTF-8 string, but, I'm going out on a limb and say that's moronic. It's always zR, zPLR, so
    // seemingly ASCII-characters, this should be safe.
  } else {
    entry_reader.read_value<u8>();
  }

  if (cie.version >= 4) {
    cie.addr_size = entry_reader.read_value<u8>();
    cie.segment_size = entry_reader.read_value<u8>();
  }

  cie.code_alignment_factor = entry_reader.read_uleb128<u64>();
  cie.data_alignment_factor = entry_reader.read_leb128<i64>();
  cie.retaddr_register = cie.retaddr_register = entry_reader.read_uleb128<u64>();
  auto auglen = 0;
  for (auto c : cie.augmentation_string.value_or("")) {
    if (c == 'z') {
      auglen = entry_reader.read_uleb128<u64>();
    }
    if (c == 'R') {
      auto fde_encoding = parse_encoding(entry_reader.read_value<u8>());
      cie.fde_encoding = fde_encoding;
    }
    if (c == 'P') {
      auto [fmt, val] = parse_encoding(entry_reader.read_value<u8>());
      ASSERT(fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr,
             "Expected personality data to be absolute pointer");
      if (fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
        cie.personality_address = entry_reader.read_value<u32>();
      }
    }
    if (c == 'L') {
      auto lsda = parse_encoding(entry_reader.read_value<u8>());
    }
  }

  cie.instructions = entry_reader.get_span(entry_reader.remaining_size());
  reader.skip(entry_reader.bytes_read());
  return cie;
}

CommonInformationEntry
read_cie(u64 length, DwarfBinaryReader &entry_reader) noexcept
{
  CIE cie;
  cie.length = length;
  cie.version = entry_reader.read_value<u8>();

  const auto has_augment = entry_reader.peek_value<i8>();
  if ((bool)has_augment) {
    cie.augmentation_string = entry_reader.read_string();
    // this is a UTF-8 string, but, I'm going out on a limb and say that's moronic. It's always zR, zPLR, so
    // seemingly ASCII-characters, this should be safe.
  } else {
    entry_reader.read_value<u8>();
  }

  if (cie.version >= 4) {
    cie.addr_size = entry_reader.read_value<u8>();
    cie.segment_size = entry_reader.read_value<u8>();
  }

  cie.code_alignment_factor = entry_reader.read_uleb128<u64>();
  cie.data_alignment_factor = entry_reader.read_leb128<i64>();
  cie.retaddr_register = cie.retaddr_register = entry_reader.read_uleb128<u64>();
  auto auglen = 0;
  for (auto c : cie.augmentation_string.value_or("")) {
    if (c == 'z') {
      auglen = entry_reader.read_uleb128<u64>();
    }
    if (c == 'R') {
      auto fde_encoding = parse_encoding(entry_reader.read_value<u8>());
      cie.fde_encoding = fde_encoding;
    }
    if (c == 'P') {
      auto [fmt, val] = parse_encoding(entry_reader.read_value<u8>());
      ASSERT(fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr,
             "Expected personality data to be absolute pointer");
      if (fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
        cie.personality_address = entry_reader.read_value<u32>();
      }
    }
    if (c == 'L') {
      auto lsda = parse_encoding(entry_reader.read_value<u8>());
    }
  }
  const auto bytes_remaining = length - entry_reader.pop_bookmark();
  cie.instructions = entry_reader.get_span(bytes_remaining);

  return cie;
}

u64
Unwinder::total_cies() const noexcept
{
  return dwarf_debug_cies.size() + elf_eh_cies.size();
}
u64
Unwinder::total_fdes() const noexcept
{
  return dwarf_unwind_infos.size() + elf_eh_unwind_infos.size();
}

Unwinder::Unwinder(ObjFile *objfile) noexcept : objfile(objfile) {}

} // namespace sym
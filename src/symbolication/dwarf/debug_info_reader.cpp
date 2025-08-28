/** LICENSE TEMPLATE */
#include "debug_info_reader.h"
#include "../objfile.h"
#include "symbolication/dwarf/die.h"
#include "symbolication/dwarf_binary_reader.h"
#include "utils/util.h"

namespace mdb::sym::dw {

UnitReader::UnitReader(UnitData *data) noexcept
    : mCompilationUnit(data), mCurrentPtr(nullptr), mFormat(data->GetHeader().Format())
{
  const auto &header = mCompilationUnit->GetHeader();
  mCurrentPtr = mCompilationUnit->GetObjectFile()->GetElf()->mDebugInfo->GetPointer(
    header.HeaderLen() + header.DebugInfoSectionOffset());
}

UnitReader::UnitReader(UnitData *data, const DieMetaData &entry) noexcept : UnitReader(data) { SeekDie(entry); }

UnitReader::UnitReader(UnitData *data, u64 offset) noexcept
    : mCompilationUnit(data), mFormat(data->GetHeader().Format())
{
  SetOffset(offset);
}

UnitReader::UnitReader(const UnitReader &o) noexcept = default;

UnitReader &
UnitReader::operator=(const UnitReader &reader) noexcept
{
  if (this == &reader) {
    return *this;
  }
  mCompilationUnit = reader.mCompilationUnit;
  mCurrentPtr = reader.mCurrentPtr;
  return *this;
}

void
UnitReader::SkipAttribute(const Abbreviation &abbreviation) noexcept
{
  auto isIndirect = false;
  auto form = abbreviation.mForm;
  do {
    isIndirect = false;
    // clang-format off
      switch (form) {
      case AttributeForm::DW_FORM_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_sec_offset: [[fallthrough]];
      case AttributeForm::DW_FORM_line_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_addr:
        mCurrentPtr += mFormat;
        break;
      case AttributeForm::DW_FORM_addr:
        mCurrentPtr += AddressSize();
        break;
      case AttributeForm::Reserved: PANIC("Can't handle RESERVED");
      case AttributeForm::DW_FORM_block2:
        mCurrentPtr += ReadIntegralValue<u16>();
        break;
      case AttributeForm::DW_FORM_block4:
        mCurrentPtr += ReadIntegralValue<u32>();
        break;

      case AttributeForm::DW_FORM_data16:
        mCurrentPtr += 16;
        break;
      case AttributeForm::DW_FORM_string:
        ReadCString();
        break;
      case AttributeForm::DW_FORM_exprloc: [[fallthrough]];
      case AttributeForm::DW_FORM_block:
        mCurrentPtr += ReadULEB128();
        break;
      case AttributeForm::DW_FORM_block1:
        mCurrentPtr += ReadIntegralValue<u8>();
        break;

      case AttributeForm::DW_FORM_strx1: [[fallthrough]];
      case AttributeForm::DW_FORM_ref1: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx1: [[fallthrough]];
      case AttributeForm::DW_FORM_data1: [[fallthrough]];
      case AttributeForm::DW_FORM_flag:
        mCurrentPtr += 1;
        break;

      case AttributeForm::DW_FORM_addrx2: [[fallthrough]];
      case AttributeForm::DW_FORM_strx2: [[fallthrough]];
      case AttributeForm::DW_FORM_ref2: [[fallthrough]];
      case AttributeForm::DW_FORM_data2:
      mCurrentPtr += 2;
        break;

      case AttributeForm::DW_FORM_addrx3: [[fallthrough]];
      case AttributeForm::DW_FORM_strx3:
        mCurrentPtr += 3;
        break;

      case AttributeForm::DW_FORM_addrx4: [[fallthrough]];
      case AttributeForm::DW_FORM_strx4: [[fallthrough]];
      case AttributeForm::DW_FORM_ref4: [[fallthrough]];
      case AttributeForm::DW_FORM_data4:
        mCurrentPtr += 4;
        break;

      case AttributeForm::DW_FORM_ref8: [[fallthrough]];
      case AttributeForm::DW_FORM_data8:
        mCurrentPtr += 8;
        break;

      case AttributeForm::DW_FORM_sdata:
        ReadLEB128();
        break;
      case AttributeForm::DW_FORM_rnglistx: [[fallthrough]];
      case AttributeForm::DW_FORM_loclistx: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx: [[fallthrough]];
      case AttributeForm::DW_FORM_strx: [[fallthrough]];
      case AttributeForm::DW_FORM_udata: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_udata:
        ReadULEB128();
        break;
      case AttributeForm::DW_FORM_indirect:
        isIndirect = true;
        form = (AttributeForm)ReadULEB128();
        break;
      case AttributeForm::DW_FORM_flag_present:
        break;
      case AttributeForm::DW_FORM_ref_sup4: PANIC("Unsupported attribute form DW_FORM_ref_sup4");
      case AttributeForm::DW_FORM_strp_sup: PANIC("Unsupported attribute form DW_FORM_strp_sup");
      case AttributeForm::DW_FORM_ref_sig8: {
        mCurrentPtr += 8;
        break;
      }
      case AttributeForm::DW_FORM_ref_sup8: PANIC("Unsupported attribute form DW_FORM_ref_sup8");
      case AttributeForm::DW_FORM_implicit_const:
        break;
      default:
        PANIC("Unknown Attribute Form");
      }
    } while (isIndirect);
  // clang-format on
}

void
UnitReader::SkipAttributes(const std::span<const Abbreviation> &attributes) noexcept
{
  for (auto [name, form, consts] : attributes) {
    auto isIndirect = false;
    do {
      isIndirect = false;
      // clang-format off
      switch (form) {
      case AttributeForm::DW_FORM_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_sec_offset: [[fallthrough]];
      case AttributeForm::DW_FORM_line_strp: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_addr:
        mCurrentPtr += mFormat;
        break;
      case AttributeForm::DW_FORM_addr:
        mCurrentPtr += mCompilationUnit->GetHeader().AddrSize();
        break;
      case AttributeForm::Reserved: PANIC("Can't handle RESERVED");
      case AttributeForm::DW_FORM_block2:
        mCurrentPtr += ReadIntegralValue<u16>();
        break;
      case AttributeForm::DW_FORM_block4:
        mCurrentPtr += ReadIntegralValue<u32>();
        break;

      case AttributeForm::DW_FORM_data16:
        mCurrentPtr += 16;
        break;
      case AttributeForm::DW_FORM_string:
        ReadCString();
        break;
      case AttributeForm::DW_FORM_exprloc: [[fallthrough]];
      case AttributeForm::DW_FORM_block:
        mCurrentPtr += ReadULEB128();
        break;
      case AttributeForm::DW_FORM_block1:
        mCurrentPtr += ReadIntegralValue<u8>();
        break;

      case AttributeForm::DW_FORM_strx1: [[fallthrough]];
      case AttributeForm::DW_FORM_ref1: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx1: [[fallthrough]];
      case AttributeForm::DW_FORM_data1: [[fallthrough]];
      case AttributeForm::DW_FORM_flag:
        mCurrentPtr += 1;
        break;

      case AttributeForm::DW_FORM_addrx2: [[fallthrough]];
      case AttributeForm::DW_FORM_strx2: [[fallthrough]];
      case AttributeForm::DW_FORM_ref2: [[fallthrough]];
      case AttributeForm::DW_FORM_data2:
      mCurrentPtr += 2;
        break;

      case AttributeForm::DW_FORM_addrx3: [[fallthrough]];
      case AttributeForm::DW_FORM_strx3:
        mCurrentPtr += 3;
        break;

      case AttributeForm::DW_FORM_addrx4: [[fallthrough]];
      case AttributeForm::DW_FORM_strx4: [[fallthrough]];
      case AttributeForm::DW_FORM_ref4: [[fallthrough]];
      case AttributeForm::DW_FORM_data4:
        mCurrentPtr += 4;
        break;

      case AttributeForm::DW_FORM_ref8: [[fallthrough]];
      case AttributeForm::DW_FORM_data8:
        mCurrentPtr += 8;
        break;

      case AttributeForm::DW_FORM_sdata:
        ReadLEB128();
        break;
      case AttributeForm::DW_FORM_rnglistx: [[fallthrough]];
      case AttributeForm::DW_FORM_loclistx: [[fallthrough]];
      case AttributeForm::DW_FORM_addrx: [[fallthrough]];
      case AttributeForm::DW_FORM_strx: [[fallthrough]];
      case AttributeForm::DW_FORM_udata: [[fallthrough]];
      case AttributeForm::DW_FORM_ref_udata:
        ReadULEB128();
        break;
      case AttributeForm::DW_FORM_indirect:
        isIndirect = true;
        form = (AttributeForm)ReadULEB128();
        break;
      case AttributeForm::DW_FORM_flag_present:
        break;
      case AttributeForm::DW_FORM_ref_sup4: PANIC("Unsupported attribute form DW_FORM_ref_sup4");
      case AttributeForm::DW_FORM_strp_sup: PANIC("Unsupported attribute form DW_FORM_strp_sup");
      case AttributeForm::DW_FORM_ref_sig8: {
        mCurrentPtr += 8;
        break;
      }
      case AttributeForm::DW_FORM_ref_sup8: PANIC("Unsupported attribute form DW_FORM_ref_sup8");
      case AttributeForm::DW_FORM_implicit_const:
        break;
      default:
        PANIC("Unknown Attribute Form");
      }
    } while (isIndirect);
    // clang-format on
  }
}

AddrPtr
UnitReader::ReadAddress() noexcept
{
  MDB_ASSERT(mCurrentPtr < mCompilationUnit->GetHeader().EndExclusive(),
    "Reader fell off of CU data section, possibly reading another CU's data");
  switch (mCompilationUnit->GetHeader().AddrSize()) {
  case 4: {
    u32 addr = *(u32 *)mCurrentPtr;
    mCurrentPtr += 4;
    return AddrPtr{ addr };
  }
  case 8: {
    u64 addr = *(u64 *)mCurrentPtr;
    mCurrentPtr += 8;
    return AddrPtr{ addr };
  }
  default:
    PANIC(std::format("Currently unsupported address size {}", mCompilationUnit->GetHeader().AddrSize()));
  }
  return { nullptr };
}

std::string_view
UnitReader::ReadString() noexcept
{
  const std::string_view str{ (const char *)mCurrentPtr };
  mCurrentPtr += (str.size() + 1);
  return str;
}

const char *
UnitReader::ReadCString() noexcept
{
  const char *start = (const char *)mCurrentPtr;
  while (*mCurrentPtr != 0) {
    ++mCurrentPtr;
  }
  ++mCurrentPtr;
  return start;
}

DataBlock
UnitReader::ReadBlock(u64 block_size) noexcept
{
  const auto tmp = mCurrentPtr;
  mCurrentPtr += block_size;
  return { .ptr = tmp, .size = block_size };
}

u64
UnitReader::BytesRead() const noexcept
{
  return static_cast<u64>(mCurrentPtr - mCompilationUnit->GetHeader().Data());
}

u64
UnitReader::ReadULEB128() noexcept
{
  u64 value;
  mCurrentPtr = DecodeUleb128(mCurrentPtr, value);
  return value;
}

i64
UnitReader::ReadLEB128() noexcept
{
  i64 value;
  mCurrentPtr = DecodeLeb128(mCurrentPtr, value);
  return value;
}

LEB128Read<u64>
UnitReader::DecodeULEB128() noexcept
{
  const auto start = mCurrentPtr;
  u64 value;
  mCurrentPtr = DecodeUleb128(mCurrentPtr, value);
  return LEB128Read<u64>{ value, static_cast<u8>(mCurrentPtr - start) };
}

LEB128Read<i64>
UnitReader::DecodeLEB128() noexcept
{
  const auto start = mCurrentPtr;
  i64 value;
  mCurrentPtr = DecodeLeb128(mCurrentPtr, value);
  return LEB128Read<i64>{ value, static_cast<u8>(mCurrentPtr - start) };
}

u64
UnitReader::ReadOffsetValue() noexcept
{
  const auto format = mCompilationUnit->GetHeader().Format();
  MDB_ASSERT(format == 4 || format == 8, "Unsupported format: {}. Offset sizes supported are 4 and 8", format);
  if (format == 4) {
    return ReadIntegralValue<u32>();
  } else {
    return ReadIntegralValue<u64>();
  }
}

u64
UnitReader::ReadSectionOffsetValue(u64 offset) const noexcept
{
  return mCompilationUnit->GetHeader().DebugInfoSectionOffset() + offset;
}

u64
UnitReader::ReadNumbBytes(u8 nBytes) noexcept
{
  MDB_ASSERT(nBytes <= 8, "Can't read more than 8 bytes when interpreting something as a u64: {}", nBytes);
  auto result = 0;
  auto shift = 0;
  while (nBytes > 0) {
    const u64 v = ReadIntegralValue<u8>();
    result |= (v << shift);
    shift += 8;
    nBytes--;
  }
  return result;
}

AddrPtr
UnitReader::ReadByIndexFromAddressTable(u64 addrIndex) const noexcept
{
  auto obj = mCompilationUnit->GetObjectFile();
  const auto header = mCompilationUnit->GetHeader();
  MDB_ASSERT(!obj->GetElf()->mDebugAddr->mSectionData->empty(), ".debug_addr expected not to be nullptr");
  const auto addrTableOffset = mCompilationUnit->AddressBase() + addrIndex * header.AddrSize();
  const auto ptr = (obj->GetElf()->mDebugAddr->mSectionData->data() + addrTableOffset);
  if (header.AddrSize() == 4) {
    const auto value = *(u32 *)ptr;
    return AddrPtr{ value };
  } else {
    const auto value = *(u64 *)ptr;
    return AddrPtr{ value };
  }
}

const char *
UnitReader::ReadByIndexFromStringTable(u64 strIndex) const noexcept
{
  const auto elf = mCompilationUnit->GetObjectFile()->GetElf();
  MDB_ASSERT(!elf->mDebugStrOffsets->mSectionData->empty(), ".debug_str_offsets expected not to be nullptr");
  const auto strBase = mCompilationUnit->StrOffsetBase();
  const auto strTableOffset = strBase.value() + strIndex * mCompilationUnit->GetHeader().Format();
  const auto ptr = (elf->mDebugStrOffsets->mSectionData->data() + strTableOffset);
  if (mCompilationUnit->GetHeader().Format() == 4) {
    const auto value = *(u32 *)ptr;
    return elf->mDebugStr->GetCString(value);
  } else {
    const auto value = *(u64 *)ptr;
    return elf->mDebugStr->GetCString(value);
  }
}

u64
UnitReader::ReadByIndexFromRangeList(u64 rangeIndex) const noexcept
{
  const auto elf = mCompilationUnit->GetObjectFile()->GetElf();
  MDB_ASSERT(!elf->mDebugRnglists->mSectionData->empty(), ".debug_str_offsets expected not to be nullptr");
  const auto rnglistOffset =
    mCompilationUnit->RangeListBase() + rangeIndex * mCompilationUnit->GetHeader().Format();
  const auto ptr = (elf->mDebugRnglists->mSectionData->data() + rnglistOffset);
  if (mCompilationUnit->GetHeader().Format() == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}
u64
UnitReader::ReadLocationListIndex(u64 rangeIndex, std::optional<u64> locListBase) const noexcept
{
  PANIC("read_loclist_index is not yet implemented. see other indirect + base calculations");
  const auto elf = mCompilationUnit->GetObjectFile()->GetElf();
  MDB_ASSERT(!elf->mDebugLoclist->mSectionData->empty(), ".debug_str_offsets expected not to be nullptr");

  const auto rngListOffset = locListBase.value_or(0) + rangeIndex * mCompilationUnit->GetHeader().Format();
  const auto ptr = (elf->mDebugLoclist->mSectionData->data() + rngListOffset);
  if (mCompilationUnit->GetHeader().Format() == 4) {
    const auto value = *(u32 *)ptr;
    return value;
  } else {
    const auto value = *(u64 *)ptr;
    return value;
  }
}

u64
UnitReader::SectionOffset() const noexcept
{
  const auto compUnitHeaderSecOffset = mCompilationUnit->GetHeader().DebugInfoSectionOffset();
  const auto firstCompUnitOffset = compUnitHeaderSecOffset + mCompilationUnit->GetHeader().HeaderLen();
  return firstCompUnitOffset + BytesRead();
}

bool
UnitReader::HasMore() const noexcept
{
  return mCurrentPtr < mCompilationUnit->GetHeader().EndExclusive();
}

void
UnitReader::SeekDie(const DieMetaData &entry) noexcept
{
  mCurrentPtr =
    mCompilationUnit->GetObjectFile()->GetElf()->mDebugInfo->begin() + entry.mSectionOffset + entry.mDieDataOffset;
}

void
UnitReader::SetOffset(u64 offset) noexcept
{
  mCurrentPtr = mCompilationUnit->GetObjectFile()->GetElf()->mDebugInfo->GetPointer(offset);
}

const Elf *
UnitReader::GetElf() const noexcept
{
  return mCompilationUnit->GetObjectFile()->GetElf();
}

const u8 *
UnitReader::RawPointer() const noexcept
{
  return mCurrentPtr;
}

ObjectFile *
UnitReader::GetObjectFile() const noexcept
{
  return mCompilationUnit->GetObjectFile();
}

AttributeValue
ReadAttributeValue(UnitReader &reader, Abbreviation abbr, const std::vector<i64> &implicit_consts) noexcept
{
  static constexpr auto IS_DWZ = false;
  MDB_ASSERT(IS_DWZ == false, ".dwo files not supported yet");
  if (abbr.IMPLICIT_CONST_INDEX != UINT8_MAX) {
    return AttributeValue{
      implicit_consts[abbr.IMPLICIT_CONST_INDEX], AttributeForm::DW_FORM_implicit_const, abbr.mName
    };
  }

  const auto elf = reader.GetElf();

  switch (abbr.mForm) {
  case AttributeForm::DW_FORM_ref_addr:
    return AttributeValue{ reader.ReadOffsetValue(), abbr.mForm, abbr.mName };
    break;
  case AttributeForm::DW_FORM_addr: {
    return AttributeValue{ reader.ReadAddress(), abbr.mForm, abbr.mName };
  }
  case AttributeForm::Reserved:
    PANIC("Can't handle RESERVED");
  case AttributeForm::DW_FORM_block2:
    return AttributeValue{ reader.ReadBlock(reader.ReadIntegralValue<u16>()), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_block4:
    return AttributeValue{ reader.ReadBlock(reader.ReadIntegralValue<u32>()), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_data2:
    return AttributeValue{ reader.ReadIntegralValue<u16>(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_data4:
    return AttributeValue{ reader.ReadIntegralValue<u32>(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_data8:
    return AttributeValue{ reader.ReadIntegralValue<u64>(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_data16:
    return AttributeValue{ reader.ReadBlock(16), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_string:
    return AttributeValue{ reader.ReadCString(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_exprloc:
    [[fallthrough]];
  case AttributeForm::DW_FORM_block: {
    const auto size = reader.ReadULEB128();
    return AttributeValue{ reader.ReadBlock(size), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_block1: {
    return AttributeValue{ reader.ReadBlock(reader.ReadIntegralValue<u8>()), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_data1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_flag:
    return AttributeValue{ reader.ReadIntegralValue<u8>(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_sdata:
    return AttributeValue{ reader.ReadLEB128(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_strp: {
    MDB_ASSERT(elf->mDebugStr != nullptr, ".debug_str expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.ReadOffsetValue();
      return AttributeValue{ (const char *)elf->mDebugStr->begin() + offset, abbr.mForm, abbr.mName };
    }
  }
  case AttributeForm::DW_FORM_line_strp: {
    MDB_ASSERT(elf->mDebugLineStr != nullptr, ".debug_line expected to be not null");
    if (!IS_DWZ) {
      const auto offset = reader.ReadOffsetValue();
      const auto ptr = (const char *)elf->mDebugLineStr->begin() + offset;
      return AttributeValue{ ptr, abbr.mForm, abbr.mName };
    }
  }
  case AttributeForm::DW_FORM_udata:
    return AttributeValue{ reader.ReadULEB128(), abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_ref1: {
    const auto offset = reader.ReadIntegralValue<u8>();
    return AttributeValue{ reader.ReadSectionOffsetValue(offset), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref2: {
    const auto offset = reader.ReadIntegralValue<u16>();
    return AttributeValue{ reader.ReadSectionOffsetValue(offset), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref4: {
    const auto offset = reader.ReadIntegralValue<u32>();
    return AttributeValue{ reader.ReadSectionOffsetValue(offset), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref8: {
    const auto offset = reader.ReadIntegralValue<u64>();
    return AttributeValue{ reader.ReadSectionOffsetValue(offset), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref_udata: {
    const auto offset = reader.ReadULEB128();
    return AttributeValue{ reader.ReadSectionOffsetValue(offset), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_indirect: {
    PANIC("Support for indirect not implemented");
    const auto newForm = (AttributeForm)reader.ReadULEB128();
    Abbreviation newAbbr{ .mName = abbr.mName, .mForm = newForm, .IMPLICIT_CONST_INDEX = UINT8_MAX };
    if (newForm == AttributeForm::DW_FORM_implicit_const) {
      MDB_ASSERT("mdb", "This implicit const as a dynamic form just FEELS wrong!");
      // const auto value = reader.leb128();
      // new_abbr.IMPLICIT_CONST_INDEX = implicit_consts.size();
      // implicit_consts.push_back(value);
    }
    return ReadAttributeValue(reader, newAbbr, implicit_consts);
  }
  case AttributeForm::DW_FORM_sec_offset: {
    const auto offset = reader.ReadOffsetValue();
    return AttributeValue{ offset, abbr.mForm, abbr.mName };
  }

  case AttributeForm::DW_FORM_flag_present:
    return AttributeValue{ (u64) true, abbr.mForm, abbr.mName };
  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_strx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_strx4: {
    const auto base = mdb::castenum(AttributeForm::DW_FORM_strx1) - 1;
    const auto bytesToRead = mdb::castenum(abbr.mForm) - base;
    const auto idx = reader.ReadNumbBytes(bytesToRead);
    return AttributeValue{ reader.ReadByIndexFromStringTable(idx), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_strx: {
    const auto idx = reader.ReadULEB128();
    return AttributeValue{ reader.ReadByIndexFromStringTable(idx), abbr.mForm, abbr.mName };
  }

  // fall through. Nasty attribute forms; beware
  case AttributeForm::DW_FORM_addrx1:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx2:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx3:
    [[fallthrough]];
  case AttributeForm::DW_FORM_addrx4: {
    MDB_ASSERT(elf->mDebugAddr != nullptr,
      ".debug_addr not read in or found in objfile {}",
      reader.GetObjectFile()->GetPathString());
    const auto base = mdb::castenum(AttributeForm::DW_FORM_addrx1) - 1;
    const auto bytesToRead = mdb::castenum(abbr.mForm) - base;
    const auto addrIndex = reader.ReadNumbBytes(bytesToRead);
    return AttributeValue{ reader.ReadByIndexFromAddressTable(addrIndex), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_addrx: {
    MDB_ASSERT(elf->mDebugAddr != nullptr,
      ".debug_addr not read in or found in objfile {}",
      reader.GetObjectFile()->GetPathString());
    const auto addr_table_index = reader.ReadULEB128();
    return AttributeValue{ reader.ReadByIndexFromAddressTable(addr_table_index), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref_sup4:
    PANIC("Unsupported attribute form DW_FORM_ref_sup4");
  case AttributeForm::DW_FORM_strp_sup:
    PANIC("Unsupported attribute form DW_FORM_strp_sup");
  case AttributeForm::DW_FORM_ref_sig8: {
    const auto offset = reader.ReadIntegralValue<u64>();
    return AttributeValue{ offset, abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_implicit_const:
    MDB_ASSERT(abbr.IMPLICIT_CONST_INDEX != UINT8_MAX, "Invalid implicit const index");
    return AttributeValue{ implicit_consts[abbr.IMPLICIT_CONST_INDEX], abbr.mForm, abbr.mName };
  case AttributeForm::DW_FORM_loclistx: {
    MDB_ASSERT(elf->mDebugLoclist != nullptr,
      ".debug_rnglists not read in or found in objfile {}",
      reader.GetObjectFile()->GetPathString());
    const auto idx = reader.ReadULEB128();
    return AttributeValue{ reader.ReadLocationListIndex(idx, {}), abbr.mForm, abbr.mName };
  }

  case AttributeForm::DW_FORM_rnglistx: {
    MDB_ASSERT(elf->mDebugRnglists != nullptr,
      ".debug_rnglists not read in or found in objfile {}",
      reader.GetObjectFile()->GetPathString());
    const auto addr_table_index = reader.ReadULEB128();
    return AttributeValue{ reader.ReadByIndexFromRangeList(addr_table_index), abbr.mForm, abbr.mName };
  }
  case AttributeForm::DW_FORM_ref_sup8:
    PANIC("Unsupported attribute form DW_FORM_ref_sup8");
    break;
  }
  PANIC("Unknown Attribute Form");
}

} // namespace mdb::sym::dw
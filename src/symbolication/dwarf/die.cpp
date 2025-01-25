/** LICENSE TEMPLATE */
#include "die.h"
#include "common.h"
#include "debug_info_reader.h"
#include "symbolication/dwarf.h"
#include "symbolication/dwarf/die_ref.h"
#include "typedefs.h"
#include "utils/logger.h"
#include "utils/util.h"
#include <emmintrin.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/enumerator.h>

static bool DwarfLog = false;

void
SetDwarfLogConfig(bool value) noexcept
{
  DwarfLog = value;
}

namespace sym::dw {

bool
IsCompileUnit(DwarfUnitType type)
{
  switch (type) {
  case DwarfUnitType::DW_UT_compile:
  case DwarfUnitType::DW_UT_partial:
    return true;
  case DwarfUnitType::UNSUPPORTED:
  case DwarfUnitType::DW_UT_skeleton:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_split_compile:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_split_type:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_lo_user:
    [[fallthrough]];
  case DwarfUnitType::DW_UT_hi_user:
    TODO_FMT("Unhandled unit type: {}", to_str(type));
  case DwarfUnitType::DW_UT_type:
    break;
  }
  return false;
}

const DieMetaData *
DieMetaData::GetParent() const noexcept
{
  if (mParentId == 0) {
    return nullptr;
  }
  return (this - mParentId);
}
const DieMetaData *
DieMetaData::Sibling() const noexcept
{
  if (mNextSibling == 0) {
    return nullptr;
  }
  return (this + mNextSibling);
}

const DieMetaData *
DieMetaData::GetChildren() const noexcept
{
  if (!mHasChildren) {
    return nullptr;
  }
  return this + 1;
}

bool
DieMetaData::IsSuperScopeVariable() const noexcept
{
  using enum DwarfTag;
  if (mTag != DW_TAG_variable) {
    return false;
  }

  auto parent_die = GetParent();
  while (parent_die != nullptr) {
    switch (parent_die->mTag) {
    case DW_TAG_subprogram:
    case DW_TAG_lexical_block:
    case DW_TAG_inlined_subroutine:
      return false;
    case DW_TAG_compile_unit:
    case DW_TAG_partial_unit:
      return true;
    default:
      break;
    }
    parent_die = parent_die->GetParent();
  }
  return false;
}

void
DieMetaData::SetParentId(u64 p_id) noexcept
{
  mParentId = p_id;
}

void
DieMetaData::SetSiblingId(u32 sib_id) noexcept
{
  mNextSibling = sib_id;
}

/*static*/ DieMetaData
DieMetaData::CreateDie(u64 sec_offset, const AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset,
                       u64 next_sibling) noexcept
{
  return DieMetaData{.mSectionOffset = sec_offset,
                     .mParentId = parent_id,
                     .mDieDataOffset = die_data_offset,
                     .mNextSibling = static_cast<u32>(next_sibling),
                     .mHasChildren = abbr.mHasChildren,
                     .mAbbreviationCode = static_cast<u16>(abbr.mCode),
                     .mTag = abbr.mTag};
}

/* static */
UnitData *
UnitData::CreateInitUnitData(ObjectFile *owningObject, UnitHeader header,
                             AbbreviationInfo::Table &&abbreviations) noexcept
{
  auto dwarfUnit = new UnitData{owningObject, header};
  dwarfUnit->SetAbbreviations(std::move(abbreviations));

  // No further init needed. If it's not a compilation unit, we don't need build directory or name
  // if it is, but it's of version 5, the Line Number Program headers will actually contain the build directory
  // in it's header (which is *MUCH* better). That way we don't need to parse the unit die. However, version 4
  // does not include that in the LNP Header, so we need to parse build directory in order to create
  // `SourceCodeFile` with a full path, by joining the build directory with the relative directory and the file
  // names. In this regard, DWARF5 is infinitely better, although this cost is just paid 1, up front for our Dwarf4
  // implementation.
  if (!dwarfUnit->IsCompilationUnitLike() || dwarfUnit->header().Version() == DwarfVersion::D5) {
    return dwarfUnit;
  }

  UnitReader reader{dwarfUnit};

  const auto die_sec_offset = reader.SectionOffset();
  const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();

  ASSERT(abbr_code <= dwarfUnit->mAbbreviation.size() && abbr_code != 0,
         "[cu=0x{:x}]: Unit DIE abbreviation code {} is invalid, max={}", dwarfUnit->SectionOffset(), abbr_code,
         dwarfUnit->mAbbreviation.size());
  auto &abbreviation = dwarfUnit->mAbbreviation[abbr_code - 1];
  const auto unitDie = DieMetaData::CreateDie(die_sec_offset, abbreviation, NONE_INDEX, uleb_sz, NONE_INDEX);
  auto [lineNumberProgramOffset, buildDirectory] = PrepareCompileUnitPreDwarf5(dwarfUnit, unitDie);
  dwarfUnit->mBuildDirectory = buildDirectory;
  dwarfUnit->mStatementListOffset = lineNumberProgramOffset;

  DBGLOG(dwarf, "[cu=0x{:x}] build directory='{}' with stmt_list offset=0x{:x}", dwarfUnit->SectionOffset(),
         dwarfUnit->mBuildDirectory ? dwarfUnit->mBuildDirectory : "could not find build directory",
         dwarfUnit->mStatementListOffset);
  return dwarfUnit;
}

bool
UnitData::IsCompilationUnitLike() const noexcept
{
  return IsCompileUnit(mUnitHeader.GetUnitType());
}

UnitData::UnitData(ObjectFile *owning_objfile, UnitHeader header) noexcept
    : mObjectFile(owning_objfile), mUnitHeader(header), mUnitDie(), mDieCollection(), mFullyLoaded(false),
      mLoadedDiesCount(0), mAbbreviation(), mLoadDiesMutex{}
{
}

void
UnitData::SetAbbreviations(AbbreviationInfo::Table &&table) noexcept
{
  mAbbreviation = std::move(table);
}

const AbbreviationInfo &
UnitData::GetAbbreviation(u32 abbreviation_code) const noexcept
{
  const auto adjusted = abbreviation_code - 1;
  ASSERT(adjusted < mAbbreviation.size(), "Abbreviation code was {} but we only have {}", abbreviation_code,
         mAbbreviation.size());
  return mAbbreviation[adjusted];
}

bool
UnitData::HasLoadedDies() const noexcept
{
  std::lock_guard lock(mLoadDiesMutex);
  return mFullyLoaded;
}

const std::vector<DieMetaData> &
UnitData::GetDies() noexcept
{
  if (mFullyLoaded) {
    return mDieCollection;
  }
  LoadDieMetadata();
  return mDieCollection;
}

void
UnitData::ClearLoadedCache() noexcept
{
  mFullyLoaded = false;
  std::lock_guard lock(mLoadDiesMutex);
  if (!mDieCollection.empty()) {
    DBGLOG(dwarf, "0x{:x} clearing dies", SectionOffset())
    mDieCollection.clear();
    // actually release the memory. Otherwise, what's the point?
    mDieCollection.shrink_to_fit();
  }
}

ObjectFile *
UnitData::GetObjectFile() const noexcept
{
  return mObjectFile;
}

const UnitHeader &
UnitData::header() const noexcept
{
  return mUnitHeader;
}

u64
UnitData::SectionOffset() const noexcept
{
  return header().DebugInfoSectionOffset();
}

u64
UnitData::UnitSize() const noexcept
{
  return header().CompilationUnitSize();
}

bool
UnitData::spans_across(u64 offset) const noexcept
{
  return header().SpansAcross(offset);
}

u64
UnitData::index_of(const DieMetaData *die) noexcept
{
  ASSERT(die != nullptr && !mDieCollection.empty(),
         "You passed a nullptr or DIE's for this unit has not been loaded");
  auto begin = mDieCollection.data();
  return die - begin;
}

std::span<const DieMetaData>
UnitData::continue_from(const DieMetaData *die) noexcept
{
  const auto index = index_of(die);
  return std::span{mDieCollection.begin() + index, mDieCollection.end()};
}

const char *
UnitData::GetBuildDirectory() const noexcept
{
  return mBuildDirectory;
}

const DieMetaData *
UnitData::GetDebugInfoEntry(u64 offset) noexcept
{
  LoadDieMetadata();

  auto it = std::lower_bound(mDieCollection.begin(), mDieCollection.end(), offset,
                             [](const dw::DieMetaData &die, u64 offset) { return die.mSectionOffset < offset; });

  ASSERT(it->mSectionOffset == offset, "failed to find die with offset 0x{:x}, found 0x{:x}", offset,
         u64{it->mSectionOffset})
  return &(*it);
}

DieReference
UnitData::GetDieReferenceByOffset(u64 offset) noexcept
{
  return DieReference{this, GetDebugInfoEntry(offset)};
}

DieReference
UnitData::GetDieByCacheIndex(u64 index) noexcept
{
  return DieReference{this, &GetDies()[index]};
}

u32
UnitData::AddressBase() noexcept
{
  if (mAddrOffset) {
    return mAddrOffset.value();
  }
  DieReference ref{this, &GetDies()[0]};
  auto base = ref.ReadAttribute(Attribute::DW_AT_addr_base);
  ASSERT(base, "Could not find Attribute::DW_AT_rnglists_base for this cu: 0x{:x}", SectionOffset());
  mAddrOffset = base.transform([](auto v) { return v.AsUnsignedValue(); });
  return mAddrOffset.value();
}

u32
UnitData::RangeListBase() noexcept
{
  if (mRngListOffset) {
    return mRngListOffset.value();
  }
  DieReference ref{this, &GetDies()[0]};
  auto base = ref.ReadAttribute(Attribute::DW_AT_rnglists_base);
  ASSERT(base, "Could not find Attribute::DW_AT_rnglists_base for this cu: 0x{:x}", SectionOffset());
  mRngListOffset = base.transform([](auto v) { return v.AsUnsignedValue(); });
  return mRngListOffset.value();
}

std::optional<u32>
UnitData::StrOffsetBase() noexcept
{
  if (mStringOffset) {
    return mStringOffset;
  }
  DieReference ref{this, &GetDies()[0]};
  auto base = ref.ReadAttribute(Attribute::DW_AT_str_offsets_base);
  ASSERT(base, "Could not find Attribute::DW_AT_str_offsets_base for this cu: 0x{:x}", SectionOffset());
  mStringOffset = base.transform(AttributeValue::ToUnsignedValue);
  return mStringOffset;
}

static constexpr auto
guess_die_count(auto unit_size) noexcept
{
  return unit_size / 24;
}

void
UnitData::LoadDieMetadata() noexcept
{
  std::lock_guard lock(mLoadDiesMutex);
  if (mFullyLoaded) {
    return;
  }

  mFullyLoaded = true;
  UnitReader reader{this};

  const auto die_sec_offset = reader.SectionOffset();
  const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();

  ASSERT(abbr_code <= mAbbreviation.size() && abbr_code != 0,
         "[cu=0x{:x}]: Unit DIE abbreviation code {} is invalid, max={}", SectionOffset(), abbr_code,
         mAbbreviation.size());
  auto &abbreviation = mAbbreviation[abbr_code - 1];
  reader.SkipAttributes(abbreviation.mAttributes);
  // Siblings and parent ids stored here
  std::vector<int> parent_node;
  std::vector<int> sibling_node;
  parent_node.push_back(0);
  sibling_node.push_back(0);
  mUnitDie = DieMetaData::CreateDie(die_sec_offset, abbreviation, NONE_INDEX, uleb_sz, NONE_INDEX);
  ASSERT(mDieCollection.empty(), "Expected dies to be empty, but wasn't! (cu=0x{:x})", SectionOffset());
  mDieCollection.reserve(mLoadedDiesCount != 0 ? mLoadedDiesCount
                                               : guess_die_count(header().CompilationUnitSize()));
  mDieCollection.push_back(mUnitDie);
  bool new_level = true;
  while (reader.HasMore()) {
    const auto die_sec_offset = reader.SectionOffset();
    const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();
    ASSERT(abbr_code <= mAbbreviation.size(), "Abbreviation code {} is invalid. Dies processed={}", abbr_code,
           mDieCollection.size());
    if (abbr_code == 0) {
      if (parent_node.empty()) {
        break;
      }
      new_level = false;
      parent_node.pop_back();
      sibling_node.pop_back();
      continue;
    }

    if (!new_level) {
      mDieCollection[sibling_node.back()].SetSiblingId(mDieCollection.size() - sibling_node.back());
      sibling_node.back() = mDieCollection.size();
    } else {
      sibling_node.push_back(mDieCollection.size());
    }

    auto &abbreviation = mAbbreviation[abbr_code - 1];
    auto new_entry = DieMetaData::CreateDie(die_sec_offset, abbreviation,
                                            mDieCollection.size() - parent_node.back(), uleb_sz, NONE_INDEX);

    reader.SkipAttributes(abbreviation.mAttributes);
    new_level = abbreviation.mHasChildren;
    if (new_level) {
      parent_node.push_back(mDieCollection.size());
    }

    mDieCollection.push_back(new_entry);
  }
  mLoadedDiesCount = mDieCollection.size();
  CDLOG(true, dwarf, "[0x{:x}] loaded {} dies", SectionOffset(), mLoadedDiesCount);
}

// Function to check if the value matches any of the 5 constants
static inline bool
HasAddressAttribute(uint16_t value1, uint16_t value2)
{
  // Load the constants into a SIMD register (pad to 8 elements)
  alignas(16) constexpr uint16_t padded_constants[8] = {
    std::to_underlying(Attribute::DW_AT_low_pc),   std::to_underlying(Attribute::DW_AT_high_pc),
    std::to_underlying(Attribute::DW_AT_entry_pc), std::to_underlying(Attribute::DW_AT_ranges),
    std::to_underlying(Attribute::DW_AT_low_pc),   std::to_underlying(Attribute::DW_AT_high_pc),
    std::to_underlying(Attribute::DW_AT_entry_pc), std::to_underlying(Attribute::DW_AT_ranges)};
  __m128i simd_constants = _mm_load_si128(reinterpret_cast<const __m128i *>(padded_constants));

  // Broadcast the input value to all elements of a SIMD register
  __m128i simd_value = _mm_set_epi16(value2, value2, value2, value2, value1, value1, value1, value1);

  // Compare the input value against the constants
  __m128i cmp_result = _mm_cmpeq_epi16(simd_value, simd_constants);

  // Move the comparison results to a bitmask
  int mask = _mm_movemask_epi8(cmp_result);

  // If any bit is set in the mask, there's a match
  return mask > 0;
}

UnitData *
prepare_unit_data(ObjectFile *obj, const UnitHeader &header) noexcept
{
  const auto abbrev_sec = obj->GetElf()->debug_abbrev;

  AbbreviationInfo::Table result{};
  const u8 *abbr_ptr = header.AbbreviationData(abbrev_sec);
  alignas(32) uint64_t attributes[64];
  while (true) {
    AbbreviationInfo &info = result.emplace_back();
    info.mIsDeclaration = false;
    info.mAbstractOrigin = false;
    abbr_ptr = decode_uleb128(abbr_ptr, info.mCode);

    // we've reached the end of this abbrev sub-section.
    if (info.mCode == 0) {
      break;
    }

    abbr_ptr = decode_uleb128(abbr_ptr, info.mTag);
    info.mHasChildren = *abbr_ptr;
    abbr_ptr++;

    const auto restore_to = abbr_ptr;
    // count declarations, because I'm guessing that what takes longest is actually the re-allocation from
    // std::vector
    auto count = 0u;
    for (;; ++count) {
      Abbreviation abbr;
      abbr_ptr = decode_uleb128(abbr_ptr, attributes[count]);
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.mForm);
      if (abbr.mForm == AttributeForm::DW_FORM_implicit_const) {
        ASSERT((u8)info.mImplicitConsts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.mImplicitConsts.size();
        i64 value = 0;
        abbr_ptr = decode_leb128(abbr_ptr, value);
      } else {
        abbr.IMPLICIT_CONST_INDEX = -1;
      }
      if (attributes[count] == 0) {
        count += 1;
        break;
      }
    }
    info.mAttributes.reserve(count);
    bool isAddressable = false;
    bool isAbstractOrigin = false;
    auto index = count;
    while (index > 2 && !isAddressable) {
      isAddressable = HasAddressAttribute(attributes[index - 1], attributes[index - 2]);
      index -= 2;
    }

    while (!isAddressable && index > 0) {
      switch (attributes[index - 1]) {
      case std::to_underlying(Attribute::DW_AT_low_pc):
      case std::to_underlying(Attribute::DW_AT_high_pc):
      case std::to_underlying(Attribute::DW_AT_entry_pc):
      case std::to_underlying(Attribute::DW_AT_ranges):
        isAddressable = true;
        break;
      default:
        index -= 1;
        break;
      }
    }

    abbr_ptr = restore_to;
    info.mIsAddressable = isAddressable;
    // read declarations
    for (size_t i = 0;; ++i) {
      Abbreviation abbr;
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.mName);
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.mForm);
      switch (abbr.mName) {
      case Attribute::DW_AT_declaration:
        info.mIsDeclaration = true;
        break;
      case Attribute::DW_AT_abstract_origin:
        info.mAbstractOrigin = true;
        break;
      default:
        break;
      }

      if (abbr.mForm == AttributeForm::DW_FORM_implicit_const) {
        ASSERT((u8)info.mImplicitConsts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.mImplicitConsts.size();
        info.mImplicitConsts.push_back(0);
        abbr_ptr = decode_leb128(abbr_ptr, info.mImplicitConsts.back());
      } else {
        abbr.IMPLICIT_CONST_INDEX = -1;
      }

      if (utils::castenum(abbr.mName) == 0) {
        break;
      }
      info.mAttributes.push_back(abbr);
    }
  }

  return UnitData::CreateInitUnitData(obj, header, std::move(result));
}

void
UnitHeadersRead::Accumulate(u64 unitSize) noexcept
{
  mMaxUnitSize = std::max(unitSize, mMaxUnitSize);
  mTotalSize += unitSize;
}

u64
UnitHeadersRead::AverageUnitSize() noexcept
{
  return mTotalSize / mUnitHeaders.size();
}

void
UnitHeadersRead::AddUnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data,
                               u64 abbrev_offset, u8 addr_size, u8 format, DwarfVersion version,
                               DwarfUnitType unit_type) noexcept
{
  mUnitHeaders.emplace_back(id, sec_offset, unit_size, die_data, abbrev_offset, addr_size, format,
                            (DwarfVersion)version, unit_type);
  Accumulate(unit_size);
}
void
UnitHeadersRead::AddTypeUnitHeader(SymbolInfoId id, u64 sec_offset, u64 unit_size, std::span<const u8> die_data,
                                   u64 abbrev_offset, u8 addr_size, u8 format, u64 type_signature,
                                   u64 type_offset) noexcept
{
  mUnitHeaders.emplace_back(id, sec_offset, unit_size, die_data, abbrev_offset, addr_size, format, type_signature,
                            type_offset);
  Accumulate(unit_size);
}

void
UnitHeadersRead::ReadUnitHeaders(ObjectFile *obj) noexcept
{
  CDLOG(DwarfLog, dwarf, "Reading {} obfile compilation unit headers", obj->GetPathString());
  const auto dbg_info = obj->GetElf()->debug_info;
  DwarfBinaryReader reader{obj->GetElf(), dbg_info->mSectionData};
  auto unit_index = 0u;
  while (reader.has_more()) {
    const auto sec_offset = reader.bytes_read();
    u64 unit_len = reader.peek_value<u32>();
    u8 format = 4u;
    auto init_len = 4;
    if ((unit_len & 0xff'ff'ff'ff) == 0xff'ff'ff'ff) {
      reader.skip(4);
      unit_len = reader.read_value<u64>();
      format = 8;
      init_len = 12;
    } else {
      reader.skip(4);
    }
    const auto total_unit_size = unit_len + init_len;
    reader.bookmark();
    const auto version = reader.read_value<u16>();
    auto unit_type = DwarfUnitType::DW_UT_compile;
    u8 addr_size = 8;
    if (version == 5) {
      unit_type = reader.read_value<DwarfUnitType>();
      addr_size = reader.read_value<u8>();
    }

    u64 abb_offs = 0u;
    switch (format) {
    case 4:
      abb_offs = reader.read_value<u32>();
      break;
    case 8:
      abb_offs = reader.read_value<u64>();
      break;
    }

    if (version < 5) {
      addr_size = reader.read_value<u8>();
    }

    switch (unit_type) {
    case DwarfUnitType::DW_UT_type: {
      const auto type_sig = reader.read_value<u64>();
      const u64 type_offset = format == 4 ? reader.read_value<u32>() : reader.read_value<u64>();
      const auto header_len = reader.pop_bookmark();
      const auto die_data_len = unit_len - header_len;
      ASSERT(header_len == 20 || header_len == 28, "Unexpected header length: {}", header_len);
      AddTypeUnitHeader({unit_index}, sec_offset, total_unit_size, reader.get_span(die_data_len), abb_offs,
                        addr_size, format, type_sig, type_offset);
    } break;
    case DwarfUnitType::DW_UT_compile:
      [[fallthrough]];
    case DwarfUnitType::DW_UT_partial: {
      const auto header_len = reader.pop_bookmark();
      if (version == 4 || version == 3) {
        ASSERT((header_len == 7 || header_len == 11), "Unexpected compilation unit header size: {}", header_len);
      } else {
        ASSERT(version == 5 && (header_len == 8 || header_len == 12),
               "Unexpected compilation unit header size: {}", header_len);
      }
      const auto die_data_len = unit_len - header_len;
      AddUnitHeader(SymbolInfoId{unit_index}, sec_offset, total_unit_size, reader.get_span(die_data_len), abb_offs,
                    addr_size, format, (DwarfVersion)version, unit_type);
    } break;
    default:
      ASSERT(false, "Unit type {} not supported yet", to_str(unit_type));
      break;
    }
    ++unit_index;
    ASSERT(reader.bytes_read() == sec_offset + unit_len + init_len,
           "Well, this is wrong. Expected to have read {} bytes, but was at {}", sec_offset + unit_len + init_len,
           reader.bytes_read());
  }
  CDLOG(DwarfLog, dwarf, "Read {} compilation unit headers", mUnitHeaders.size());
}

std::span<UnitHeader>
UnitHeadersRead::Headers() noexcept
{
  return mUnitHeaders;
}
} // namespace sym::dw
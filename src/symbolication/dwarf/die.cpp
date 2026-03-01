/** LICENSE TEMPLATE */

#include "die.h"

// mdb
#include <common.h>
#include <common/typedefs.h>
#include <symbolication/dwarf/debug_info_reader.h>
#include <symbolication/dwarf/die_ref.h>
#include <symbolication/dwarf_attribute_value.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/elf.h>
#include <symbolication/objfile.h>
#include <utils/enumerator.h>
#include <utils/todo.h>
#include <utils/util.h>

// system
#include <emmintrin.h>

static bool DwarfLog = false;

namespace mdb {

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

  const DieMetaData *parent_die = GetParent();
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
DieMetaData::CreateDie(
  u64 sec_offset, const AbbreviationInfo &abbr, u64 parent_id, u64 die_data_offset, u64 next_sibling) noexcept
{
  return DieMetaData{ .mSectionOffset = sec_offset,
    .mParentId = parent_id,
    .mDieDataOffset = die_data_offset,
    .mNextSibling = static_cast<u32>(next_sibling),
    .mHasChildren = abbr.mHasChildren,
    .mAbbreviationCode = static_cast<u16>(abbr.mCode),
    .mTag = abbr.mTag };
}

/* static */
UnitData *
UnitData::CreateInitUnitData(
  ObjectFile *owningObject, UnitHeader header, AbbreviationInfo::Table &&abbreviations) noexcept
{
  auto *dwarfUnit = new UnitData{ owningObject, header };
  dwarfUnit->SetAbbreviations(std::move(abbreviations));

  // No further init needed. If it's not a compilation unit, we don't need build directory or name
  // if it is, but it's of version 5, the Line Number Program headers will actually contain the build directory
  // in it's header (which is *MUCH* better). That way we don't need to parse the unit die. However, version 4
  // does not include that in the LNP Header, so we need to parse build directory in order to create
  // `SourceCodeFile` with a full path, by joining the build directory with the relative directory and the file
  // names. In this regard, DWARF5 is infinitely better, although this cost is just paid 1, up front for our Dwarf4
  // implementation.
  if (!dwarfUnit->IsCompilationUnitLike() || dwarfUnit->GetHeader().Version() == DwarfVersion::D5) {
    return dwarfUnit;
  }

  UnitReader reader{ dwarfUnit };

  const auto die_sec_offset = reader.SectionOffset();
  const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();

  MDB_ASSERT(abbr_code <= dwarfUnit->mAbbreviation.size() && abbr_code != 0,
    "[cu={}]: Unit DIE abbreviation code {} is invalid, max={}",
    dwarfUnit->SectionOffset(),
    abbr_code,
    dwarfUnit->mAbbreviation.size());
  auto &abbreviation = dwarfUnit->mAbbreviation[abbr_code - 1];
  const auto unitDie = DieMetaData::CreateDie(die_sec_offset, abbreviation, NONE_INDEX, uleb_sz, NONE_INDEX);
  auto [lineNumberProgramOffset, buildDirectory] = PrepareCompileUnitPreDwarf5(dwarfUnit, unitDie);
  dwarfUnit->mBuildDirectory = buildDirectory;
  dwarfUnit->mStatementListOffset = lineNumberProgramOffset;

  DBGLOG(dwarf,
    "[cu={}] build directory='{}' with stmt_list offset=0x{:x}",
    dwarfUnit->SectionOffset(),
    dwarfUnit->mBuildDirectory ? dwarfUnit->mBuildDirectory : "could not find build directory",
    dwarfUnit->mStatementListOffset);
  return dwarfUnit;
}

bool
UnitData::IsCompilationUnitLike() const noexcept
{
  return IsCompileUnit(mUnitHeader.GetUnitType());
}

UnitData::UnitData(ObjectFile *owningObjectfile, UnitHeader header) noexcept
    : mObjectFile(owningObjectfile), mUnitHeader(header), mUnitDie(), mFullyLoaded(false), mLoadedDiesCount(0)
{
}

void
UnitData::SetAbbreviations(AbbreviationInfo::Table &&table) noexcept
{
  mAbbreviation = std::move(table);
}

const AbbreviationInfo &
UnitData::GetAbbreviation(u32 abbreviationCode) const noexcept
{
  const auto adjusted = abbreviationCode - 1;
  MDB_ASSERT(adjusted < mAbbreviation.size(),
    "Abbreviation code was {} but we only have {}",
    abbreviationCode,
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
    DBGLOG(dwarf, "{} clearing dies", SectionOffset());
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
UnitData::GetHeader() const noexcept
{
  return mUnitHeader;
}

Offset
UnitData::SectionOffset() const noexcept
{
  return GetHeader().DebugInfoSectionOffset();
}

u64
UnitData::UnitSize() const noexcept
{
  return GetHeader().CompilationUnitSize();
}

bool
UnitData::SpansAcrossOffset(u64 offset) const noexcept
{
  return GetHeader().SpansAcross(offset);
}

u64
UnitData::IndexOf(const DieMetaData *die) noexcept
{
  MDB_ASSERT(
    die != nullptr && !mDieCollection.empty(), "You passed a nullptr or DIE's for this unit has not been loaded");
  DieMetaData *begin = mDieCollection.data();
  return die - begin;
}

std::span<const DieMetaData>
UnitData::continue_from(const DieMetaData *die) noexcept
{
  const auto index = IndexOf(die);
  return std::span{ mDieCollection.begin() + static_cast<i64>(index), mDieCollection.end() };
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

  auto it = std::lower_bound(
    mDieCollection.begin(), mDieCollection.end(), offset, [](const dw::DieMetaData &die, u64 offset) {
      return die.mSectionOffset < offset;
    });

  MDB_ASSERT(it->mSectionOffset == offset,
    "failed to find die with offset 0x{:x}, found 0x{:x}",
    offset,
    u64{ it->mSectionOffset })
  return &(*it);
}

DieReference
UnitData::GetDieReferenceByOffset(u64 offset) noexcept
{
  return DieReference{ this, GetDebugInfoEntry(offset) };
}

DieReference
UnitData::GetDieByCacheIndex(u64 index) noexcept
{
  return DieReference{ this, &GetDies()[index] };
}

u32
UnitData::AddressBase() noexcept
{
  if (mAddrOffset) {
    return mAddrOffset.value();
  }
  DieReference ref{ this, GetDies().data() };
  auto base = ref.ReadAttribute(Attribute::DW_AT_addr_base);
  MDB_ASSERT(base, "Could not find Attribute::DW_AT_rnglists_base for this cu: {}", SectionOffset());
  mAddrOffset = base.transform([](const auto &v) { return v.AsUnsignedValue(); });
  return mAddrOffset.value();
}

u32
UnitData::RangeListBase() noexcept
{
  if (mRngListOffset) {
    return mRngListOffset.value();
  }
  DieReference ref{ this, GetDies().data() };
  auto base = ref.ReadAttribute(Attribute::DW_AT_rnglists_base);
  MDB_ASSERT(base, "Could not find Attribute::DW_AT_rnglists_base for this cu: {}", SectionOffset());
  mRngListOffset = base.transform([](const auto &v) { return v.AsUnsignedValue(); });
  return mRngListOffset.value();
}

std::optional<u32>
UnitData::StrOffsetBase() noexcept
{
  if (mStringOffset) {
    return mStringOffset;
  }
  DieReference ref{ this, GetDies().data() };
  auto base = ref.ReadAttribute(Attribute::DW_AT_str_offsets_base);
  MDB_ASSERT(base, "Could not find Attribute::DW_AT_str_offsets_base for this cu: {}", SectionOffset());
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
  UnitReader reader{ this };

  const auto dieSectionOffset = reader.SectionOffset();
  const auto [abbr_code, uleb_sz] = reader.DecodeULEB128();

  MDB_ASSERT(abbr_code <= mAbbreviation.size() && abbr_code != 0,
    "[cu={}]: Unit DIE abbreviation code {} is invalid, max={}",
    SectionOffset(),
    abbr_code,
    mAbbreviation.size());
  auto &abbreviation = mAbbreviation[abbr_code - 1];
  reader.SkipAttributes(abbreviation.mAttributes);
  // Siblings and parent ids stored here
  std::vector<int> parentNode;
  std::vector<int> siblingNode;
  parentNode.push_back(0);
  siblingNode.push_back(0);
  mUnitDie = DieMetaData::CreateDie(dieSectionOffset, abbreviation, NONE_INDEX, uleb_sz, NONE_INDEX);
  MDB_ASSERT(mDieCollection.empty(), "Expected dies to be empty, but wasn't! (cu={})", SectionOffset());
  mDieCollection.reserve(
    mLoadedDiesCount != 0 ? mLoadedDiesCount : guess_die_count(GetHeader().CompilationUnitSize()));
  mDieCollection.push_back(mUnitDie);
  bool new_level = true;
  while (reader.HasMore()) {
    const auto dieSecOffset = reader.SectionOffset();
    const auto [abbreviationCode, uleb_sz] = reader.DecodeULEB128();
    MDB_ASSERT(abbreviationCode <= mAbbreviation.size(),
      "Abbreviation code {} is invalid. Dies processed={}",
      abbreviationCode,
      mDieCollection.size());
    if (abbreviationCode == 0) {
      if (parentNode.empty()) {
        break;
      }
      new_level = false;
      parentNode.pop_back();
      siblingNode.pop_back();
      continue;
    }

    if (!new_level) {
      mDieCollection[siblingNode.back()].SetSiblingId(mDieCollection.size() - siblingNode.back());
      siblingNode.back() = mDieCollection.size();
    } else {
      siblingNode.push_back(mDieCollection.size());
    }

    auto &abbreviation = mAbbreviation[abbreviationCode - 1];
    auto new_entry = DieMetaData::CreateDie(
      dieSecOffset, abbreviation, mDieCollection.size() - parentNode.back(), uleb_sz, NONE_INDEX);

    reader.SkipAttributes(abbreviation.mAttributes);
    new_level = abbreviation.mHasChildren;
    if (new_level) {
      parentNode.push_back(mDieCollection.size());
    }

    mDieCollection.push_back(new_entry);
  }
  mLoadedDiesCount = mDieCollection.size();
  CDLOG(true, dwarf, "[{}] loaded {} dies", SectionOffset(), mLoadedDiesCount);
}

// Function to check if the value matches any of the 5 constants
static inline bool
HasAddressAttribute(uint16_t value1, uint16_t value2)
{
  // Load the constants into a SIMD register (pad to 8 elements)
  alignas(16) constexpr uint16_t padded_constants[8] = { std::to_underlying(Attribute::DW_AT_low_pc),
    std::to_underlying(Attribute::DW_AT_high_pc),
    std::to_underlying(Attribute::DW_AT_entry_pc),
    std::to_underlying(Attribute::DW_AT_ranges),
    std::to_underlying(Attribute::DW_AT_low_pc),
    std::to_underlying(Attribute::DW_AT_high_pc),
    std::to_underlying(Attribute::DW_AT_entry_pc),
    std::to_underlying(Attribute::DW_AT_ranges) };
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
PrepareUnitData(ObjectFile *obj, const UnitHeader &header) noexcept
{
  const ElfSection *abbrev_sec = obj->GetElf()->mDebugAbbrev;

  AbbreviationInfo::Table result{};
  const u8 *abbreviationPtr = header.AbbreviationData(abbrev_sec);
  alignas(32) uint64_t attributes[64];
  while (true) {
    AbbreviationInfo &info = result.emplace_back();
    info.mIsDeclaration = false;
    info.mAbstractOrigin = false;
    abbreviationPtr = DecodeUleb128(abbreviationPtr, info.mCode);

    // we've reached the end of this abbrev sub-section.
    if (info.mCode == 0) {
      break;
    }

    abbreviationPtr = DecodeUleb128(abbreviationPtr, info.mTag);
    info.mHasChildren = *abbreviationPtr;
    abbreviationPtr++;

    const u8 *restoreTo = abbreviationPtr;
    // count declarations, because I'm guessing that what takes longest is actually the re-allocation from
    // std::vector
    size_t count = 0;
    for (;; ++count) {
      Abbreviation abbr;
      abbreviationPtr = DecodeUleb128(abbreviationPtr, attributes[count]);
      abbreviationPtr = DecodeUleb128(abbreviationPtr, abbr.mForm);
      if (abbr.mForm == AttributeForm::DW_FORM_implicit_const) {
        MDB_ASSERT((u8)info.mImplicitConsts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.mImplicitConsts.size();
        i64 value = 0;
        abbreviationPtr = DecodeLeb128(abbreviationPtr, value);
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

    abbreviationPtr = restoreTo;
    info.mIsAddressable = isAddressable;
    // read declarations
    for (;;) {
      Abbreviation abbr;
      abbreviationPtr = DecodeUleb128(abbreviationPtr, abbr.mName);
      abbreviationPtr = DecodeUleb128(abbreviationPtr, abbr.mForm);
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
        MDB_ASSERT((u8)info.mImplicitConsts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.mImplicitConsts.size();
        info.mImplicitConsts.push_back(0);
        abbreviationPtr = DecodeLeb128(abbreviationPtr, info.mImplicitConsts.back());
      } else {
        abbr.IMPLICIT_CONST_INDEX = -1;
      }

      if (mdb::castenum(abbr.mName) == 0) {
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
UnitHeadersRead::AddUnitHeader(SymbolInfoId id,
  u64 sectionOffset,
  u64 unitSize,
  std::span<const u8> dieData,
  u64 abbreviationOffset,
  u8 addrSize,
  u8 format,
  DwarfVersion version,
  DwarfUnitType unitType) noexcept
{
  mUnitHeaders.emplace_back(
    id, sectionOffset, unitSize, dieData, abbreviationOffset, addrSize, format, (DwarfVersion)version, unitType);
  Accumulate(unitSize);
}
void
UnitHeadersRead::AddTypeUnitHeader(SymbolInfoId id,
  u64 sectionOffset,
  u64 unitSize,
  std::span<const u8> dieData,
  u64 abbreviationOffset,
  u8 addrSize,
  u8 format,
  u64 typeSignature,
  u64 typeOffset) noexcept
{
  mUnitHeaders.emplace_back(
    id, sectionOffset, unitSize, dieData, abbreviationOffset, addrSize, format, typeSignature, typeOffset);
  Accumulate(unitSize);
}

void
UnitHeadersRead::ReadUnitHeaders(ObjectFile *obj) noexcept
{
  CDLOG(DwarfLog, dwarf, "Reading {} obfile compilation unit headers", obj->GetPathString());
  const ElfSection *dbgInfo = obj->GetElf()->mDebugInfo;
  DwarfBinaryReader reader{ obj->GetElf(), dbgInfo->mSectionData };
  u32 unitIndex = 0;
  while (reader.HasMore()) {
    const auto secOffset = reader.BytesRead();
    u64 unitLength = reader.PeekValue<u32>();
    u8 format = 4;
    auto initLength = 4;
    if ((unitLength & 0xff'ff'ff'ff) == 0xff'ff'ff'ff) {
      reader.Skip(4);
      unitLength = reader.ReadValue<u64>();
      format = 8;
      initLength = 12;
    } else {
      reader.Skip(4);
    }
    const auto totalUnitSize = unitLength + initLength;
    reader.Bookmark();
    const auto version = reader.ReadValue<u16>();
    auto unitType = DwarfUnitType::DW_UT_compile;
    u8 addrSize = 8;
    if (version == 5) {
      unitType = reader.ReadValue<DwarfUnitType>();
      addrSize = reader.ReadValue<u8>();
    }

    u64 abbOffset = 0u;
    switch (format) {
    case 4:
      abbOffset = reader.ReadValue<u32>();
      break;
    case 8:
      abbOffset = reader.ReadValue<u64>();
      break;
    }

    if (version < 5) {
      addrSize = reader.ReadValue<u8>();
    }

    switch (unitType) {
    case DwarfUnitType::DW_UT_type: {
      const auto type_sig = reader.ReadValue<u64>();
      const u64 type_offset = format == 4 ? reader.ReadValue<u32>() : reader.ReadValue<u64>();
      const auto header_len = reader.PopBookmark();
      const auto die_data_len = unitLength - header_len;
      MDB_ASSERT(header_len == 20 || header_len == 28, "Unexpected header length: {}", header_len);
      AddTypeUnitHeader({ unitIndex },
        secOffset,
        totalUnitSize,
        reader.GetSpan(die_data_len),
        abbOffset,
        addrSize,
        format,
        type_sig,
        type_offset);
    } break;
    case DwarfUnitType::DW_UT_compile:
      [[fallthrough]];
    case DwarfUnitType::DW_UT_partial: {
      const auto header_len = reader.PopBookmark();
      if (version == 4 || version == 3) {
        MDB_ASSERT(
          (header_len == 7 || header_len == 11), "Unexpected compilation unit header size: {}", header_len);
      } else {
        MDB_ASSERT(version == 5 && (header_len == 8 || header_len == 12),
          "Unexpected compilation unit header size: {}",
          header_len);
      }
      const auto die_data_len = unitLength - header_len;
      AddUnitHeader(SymbolInfoId{ unitIndex },
        secOffset,
        totalUnitSize,
        reader.GetSpan(die_data_len),
        abbOffset,
        addrSize,
        format,
        (DwarfVersion)version,
        unitType);
    } break;
    default:
      MDB_ASSERT(false, "Unit type {} not supported yet", to_str(unitType));
      break;
    }
    ++unitIndex;
    MDB_ASSERT(reader.BytesRead() == secOffset + unitLength + initLength,
      "Well, this is wrong. Expected to have read {} bytes, but was at {}",
      secOffset + unitLength + initLength,
      reader.BytesRead());
  }
  CDLOG(DwarfLog, dwarf, "Read {} compilation unit headers", mUnitHeaders.size());
}

std::span<UnitHeader>
UnitHeadersRead::Headers() noexcept
{
  return mUnitHeaders;
}
} // namespace sym::dw
} // namespace mdb
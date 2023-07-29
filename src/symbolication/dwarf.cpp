#include "dwarf.h"
#include "cu.h"
#include "dwarf_defs.h"
#include <algorithm>
#include <cstdint>
#include <utility>
#include <variant>

constexpr bool
DEBUG_SANITIZE_DWARF_NAME(u16)
{
  return true;
}

std::unique_ptr<CUProcessor>
prepare_cu_processing(ObjectFile *obj_file, const CompileUnitHeader &header, TraceeController *target)
{
  const auto abbrev_sec = obj_file->parsed_elf->debug_abbrev;

  AbbreviationInfo::Table result{};

  const u8 *abbr_ptr = abbrev_sec->m_section_ptr + header.abbrev_offset;

  while (true) {
    AbbreviationInfo info;
    abbr_ptr = decode_uleb128(abbr_ptr, info.code);

    // we've reached the end of this abbrev sub-section.
    if (info.code == 0) {
      break;
    }

    abbr_ptr = decode_uleb128(abbr_ptr, info.tag);
    info.has_children = *abbr_ptr;
    abbr_ptr++;

    // read declarations
    for (;;) {
      Abbreviation abbr;
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.name);
      abbr_ptr = decode_uleb128(abbr_ptr, abbr.form);
      if (abbr.form == AttributeForm::DW_FORM_implicit_const) {
        ASSERT((u8)info.implicit_consts.size() != UINT8_MAX, "Maxed out IMPLICIT const entries!");
        abbr.IMPLICIT_CONST_INDEX = info.implicit_consts.size();
        info.implicit_consts.push_back(0);
        abbr_ptr = decode_leb128(abbr_ptr, info.implicit_consts.back());
      } else {
        abbr.IMPLICIT_CONST_INDEX = -1;
      }
      if (std::to_underlying(abbr.name) == 0) {
        break;
      }
      ASSERT(DEBUG_SANITIZE_DWARF_NAME(std::to_underlying(abbr.name)), "Abbreviation Name Is Invalid: 0x{:x}",
             std::to_underlying(abbr.name));
      info.attributes.push_back(abbr);
    }
    result.push_back(info);
  }
  return std::make_unique<CUProcessor>(obj_file, header, std::move(result), header.cu_index, target);
}

std::uintptr_t
AttributeValue::address() const noexcept
{
  return value.addr;
}
std::string_view
AttributeValue::string() const noexcept
{
  return value.str;
}
DataBlock
AttributeValue::block() const noexcept
{
  return value.block;
}
u64
AttributeValue::unsigned_value() const noexcept
{
  return value.u;
}
i64
AttributeValue::signed_value() const noexcept
{
  return value.i;
}

void
DebugInfoEntry::debug_dump(int indent) const noexcept
{
  std::string fill(indent, ' ');
  fmt::print("{} [{}] {}\n", fill, abbreviation_code, to_str(this->tag));
  for (const auto &att : attributes) {
    fmt::println("{} | {} {}", fill, to_str(att.name), to_str(att.form));
  }
  fmt::println("---");
  for (const auto &ch : children) {
    ch->debug_dump(indent + 1);
  }
}
#include "dwarf.h"
#include "dwarf/cu_processing.h"

// SYMBOLS namespace
namespace sym {
constexpr bool
DEBUG_SANITIZE_DWARF_NAME(u16)
{
  return true;
}

std::unique_ptr<dw::CUProcessor>
prepare_cu_processing(ObjectFile *obj_file, const dw::CompileUnitHeader &header, TraceeController *target)
{
  const auto abbrev_sec = obj_file->elf()->debug_abbrev;

  dw::AbbreviationInfo::Table result{};

  const u8 *abbr_ptr = abbrev_sec->m_section_ptr + header.abbrev_offset;

  while (true) {
    dw::AbbreviationInfo info;
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
      dw::Abbreviation abbr;
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
  return std::make_unique<dw::CUProcessor>(obj_file, header, std::move(result), header.cu_index, target);
}
} // namespace sym
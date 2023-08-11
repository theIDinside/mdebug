#pragma once
#include "../utils/macros.h"
#include <cstdint>
#include <fmt/core.h>
#include <string_view>

enum class DwarfVersion : std::uint8_t
{
  D2 = 2,
  D3 = 3,
  D4 = 4,
  D5 = 5,
};

// Macro that defines enumerator values N.B - the undef must be at the end of this file or all sorts of hell can
// break loose
#define ITEM(Name, Value) Name = Value,

enum class Attribute : std::uint16_t
{
#define DW_ATTRIBUTE
#include "../defs/dwarf.defs"
#undef DW_ATTRIBUTE
};

enum class AttributeForm : std::uint8_t
{
#define DW_ATTRIBUTE_FORM
#include "../defs/dwarf.defs"
#undef DW_ATTRIBUTE_FORM
};

enum class BaseTypeAttributeEncoding : std::uint32_t
{
#define DW_BASETYPE_ENCODING
#include "../defs/dwarf.defs"
#undef DW_BASETYPE_ENCODING
};

enum class DecimalSignEncoding : std::uint32_t
{
#define DW_DECIMAL_ENCODING
#include "../defs/dwarf.defs"
#undef DW_DECIMAL_ENCODING
};

enum class EndianityEncoding : std::uint32_t
{
#define DW_ENDIANITY_ENCODING
#include "../defs/dwarf.defs"
#undef DW_ENDIANITY_ENCODING
};

enum class AccessibilityEncoding : std::uint32_t
{
#define DW_ACCESSIBILITY_ENCODING
#include "../defs/dwarf.defs"
#undef DW_ACCESSIBILITY_ENCODING
};

enum class VisibilityEncoding : std::uint32_t
{
#define DW_VIS_ENCODING
#include "../defs/dwarf.defs"
#undef DW_VIS_ENCODING
};

enum class VirtualityEncoding : std::uint32_t
{
#define DW_VIRTUALITY_ENCODING
#include "../defs/dwarf.defs"
#undef DW_VIRTUALITY_ENCODING
};

enum class SourceLanguage : std::uint32_t
{
#define DW_SOURCE_LANGUAGE
#include "../defs/dwarf.defs"
#undef DW_SOURCE_LANGUAGE
};

enum class IdentifierCaseEncoding : std::uint32_t
{
#define DW_IDENT_CASE_ENCODING
#include "../defs/dwarf.defs"
#undef DW_IDENT_CASE_ENCODING
};

enum class CallingConventionEncoding : std::uint32_t
{
#define DW_CALL_CONVENTION_ENCODING
#include "../defs/dwarf.defs"
#undef DW_CALL_CONVENTION_ENCODING
};

enum class InlineCodes : std::uint32_t
{
#define DW_INLINE_CODES
#include "../defs/dwarf.defs"
#undef DW_INLINE_CODES
};

enum class ArrayOrdering : std::uint32_t
{
#define DW_ARRAY_ORDERING
#include "../defs/dwarf.defs"
#undef DW_ARRAY_ORDERING
};

enum class DiscriminantList : std::uint32_t
{
#define DW_DISCRIMINANT_LIST
#include "../defs/dwarf.defs"
#undef DW_DISCRIMINANT_LIST
};

enum class NameIndexTable : std::uint32_t
{
#define DW_NAME_INDEX_TABLE
#include "../defs/dwarf.defs"
#undef DW_NAME_INDEX_TABLE
};

enum class DefaultedMemberEncoding : std::uint32_t
{
#define DW_DEFAULT_MEMBER_ENCODING
#include "../defs/dwarf.defs"
#undef DW_DEFAULT_MEMBER_ENCODING
};

enum class DwarfUnitType : std::uint8_t
{
#define DW_DWARF_UNIT_TYPE
#include "../defs/dwarf.defs"
#undef DW_DWARF_UNIT_TYPE
};

enum class DwarfTag : std::uint16_t
{
#define DW_DWARF_TAG
#include "../defs/dwarf.defs"
#undef DW_DWARF_TAG
};

enum class RangeListEntry : std::uint8_t
{
#define DW_RANGE_LIST_ENTRY
#include "../defs/dwarf.defs"
#undef DW_RANGE_LIST_ENTRY
};

enum class LineNumberProgramOpCode : std::uint8_t
{
#define DW_LNP_STANDARD_OPCODES
#include "../defs/dwarf.defs"
#undef DW_LNP_STANDARD_OPCODES
};

enum class LineNumberProgramContent : std::uint16_t
{
#define DW_LNP_CONTENT
#include "../defs/dwarf.defs"
#undef DW_LNP_CONTENT
};

enum class LineNumberProgramExtendedOpCode : std::uint8_t
{
#define DW_LNP_EXTENDED_OPCODES
#include "../defs/dwarf.defs"
#undef DW_LNP_EXTENDED_OPCODES
};

enum class DwarfCallFrame : std::uint8_t
{
#define DW_CALLFRAME
#include "../defs/dwarf.defs"
#undef DW_CALLFRAME
};

enum class DwarfExceptionHeaderEncoding : std::uint8_t
{
#define DW_EXCEPTION_HEADER_ENCODING
#include "../defs/dwarf.defs"
#undef DW_EXCEPTION_HEADER_ENCODING
};

enum class DwarfExceptionHeaderApplication : std::uint8_t
{
#define DW_EXCEPTION_HEADER_APPLICATION
#include "../defs/dwarf.defs"
#undef DW_EXCEPTION_HEADER_APPLICATION
};

enum class DwarfOp : std::uint8_t
{
#define DW_EXPR
#include "../defs/dwarf.defs"
#undef DW_EXPR
};

// END OF ENUM DEFINITIONS
#undef ITEM

// STRING REPRESENTATION OF DEFINITION
#define ITEM(Name, Value)                                                                                         \
  case Name:                                                                                                      \
    return #Name;

constexpr std::string_view
to_str(RangeListEntry entry)
{
#define DW_RANGE_LIST_ENTRY
  using enum RangeListEntry;
  switch (entry) {
#include "../defs/dwarf.defs"
  }
#undef DW_RANGE_LIST_ENTRY
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(DwarfCallFrame opcode)
{
#define DW_CALLFRAME
  using enum DwarfCallFrame;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_CALLFRAME
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(DwarfExceptionHeaderEncoding opcode)
{
#define DW_EXCEPTION_HEADER_ENCODING
  using enum DwarfExceptionHeaderEncoding;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_EXCEPTION_HEADER_ENCODING
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(DwarfExceptionHeaderApplication opcode)
{
#define DW_EXCEPTION_HEADER_APPLICATION

  using enum DwarfExceptionHeaderApplication;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_EXCEPTION_HEADER_APPLICATION
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(DwarfOp opcode)
{
#define DW_EXPR

  using enum DwarfOp;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_EXPR
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(LineNumberProgramExtendedOpCode opcode)
{
#define DW_LNP_EXTENDED_OPCODES
  using enum LineNumberProgramExtendedOpCode;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_LNP_EXTENDED_OPCODES
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(LineNumberProgramOpCode opcode)
{
#define DW_LNP_STANDARD_OPCODES
  using enum LineNumberProgramOpCode;
  switch (opcode) {
#include "../defs/dwarf.defs"
  }
#undef DW_LNP_STANDARD_OPCODES
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(LineNumberProgramContent content)
{
#define DW_LNP_CONTENT
  using enum LineNumberProgramContent;
  switch (content) {
#include "../defs/dwarf.defs"
  }
#undef DW_LNP_CONTENT
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(Attribute attr) noexcept
{
#define DW_ATTRIBUTE
  using enum Attribute;
  switch (attr) {
#include "../defs/dwarf.defs"
  }
#undef DW_ATTRIBUTE
}

constexpr std::string_view
to_str(AttributeForm attr) noexcept
{
#define DW_ATTRIBUTE_FORM
  using enum AttributeForm;
  switch (attr) {
#include "../defs/dwarf.defs"
  }
#undef DW_ATTRIBUTE_FORM
  DEAL_WITH_SHITTY_GCC
}

constexpr std::string_view
to_str(DwarfTag attr) noexcept
{
#define DW_DWARF_TAG
  using enum DwarfTag;
  switch (attr) {
#include "../defs/dwarf.defs"
  }
#undef DW_DWARF_TAG
  DEAL_WITH_SHITTY_GCC
}

#undef ITEM

namespace fmt {
template <> struct formatter<Attribute>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(Attribute const &attribute, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{}", to_str(attribute));
  }
};

template <> struct formatter<AttributeForm>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(AttributeForm const &form, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{}", to_str(form));
  }
};

template <> struct formatter<DwarfTag>
{
  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(DwarfTag const &tag, FormatContext &ctx)
  {
    return fmt::format_to(ctx.out(), "{}", to_str(tag));
  }
};

} // namespace fmt
#pragma once
#include <cstdint>

enum class Attribute : std::uint16_t
{
  DW_AT_sibling = 0x01,
  DW_AT_location = 0x02,
  DW_AT_name = 0x03,
  Reserved1 = 0x04,
  Reserved2 = 0x05,
  Reserved3 = 0x06,
  Reserved4 = 0x07,
  Reserved5 = 0x08,
  DW_AT_ordering = 0x09,
  Reserved6 = 0x0a,
  DW_AT_byte_size = 0x0b,
  Reserved7 = 0x0c2,
  DW_AT_bit_size = 0x0d,
  Reserved8 = 0x0e,
  Reserved9 = 0x0f,
  DW_AT_stmt_list = 0x10,
  DW_AT_low_pc = 0x11,
  DW_AT_high_pc = 0x12,
  DW_AT_language = 0x13,
  Reserved10 = 0x14,
  DW_AT_discr = 0x15,
  DW_AT_discr_value = 0x16,
  DW_AT_visibility = 0x17,
  DW_AT_import = 0x18,
  DW_AT_string_length = 0x19,
  DW_AT_common_reference = 0x1a,
  DW_AT_comp_dir = 0x1b,
  DW_AT_const_value = 0x1c,
  DW_AT_containing_type = 0x1d,
  DW_AT_default_value = 0x1e,
  Reserved11 = 0x1f,
  DW_AT_inline = 0x20,
  DW_AT_is_optional = 0x21,
  DW_AT_lower_bound = 0x22,
  Reserved12 = 0x23,
  Reserved13 = 0x24,
  DW_AT_producer = 0x25,
  Reserved14 = 0x26,
  DW_AT_prototyped = 0x27,
  Reserved15 = 0x28,
  Reserved16 = 0x29,
  DW_AT_return_addr = 0x2a,
  Reserved17 = 0x2b,
  DW_AT_start_scope = 0x2c,
  Reserved18 = 0x2d,
  DW_AT_bit_stride = 0x2e,
  DW_AT_upper_bound = 0x2f,
  Reserved19 = 0x30,
  DW_AT_abstract_origin = 0x31,
  DW_AT_accessibility = 0x32,
  DW_AT_address_class = 0x33,
  DW_AT_artificial = 0x34,
  DW_AT_base_types = 0x35,
  DW_AT_calling_convention = 0x36,
  DW_AT_count = 0x37,
  DW_AT_data_member_location = 0x38,
  DW_AT_decl_column = 0x39,
  DW_AT_decl_file = 0x3a,
  DW_AT_decl_line = 0x3b,
  DW_AT_declaration = 0x3c,
  DW_AT_discr_list = 0x3d,
  DW_AT_encoding = 0x3e,
  DW_AT_external = 0x3f,
  DW_AT_frame_base = 0x40,
  DW_AT_friend = 0x41,
  DW_AT_identifier_case = 0x42,
  Reserved20 = 0x433,
  DW_AT_namelist_item = 0x44,
  DW_AT_priority = 0x45,
  DW_AT_segment = 0x46,
  DW_AT_specification = 0x47,
  DW_AT_static_link = 0x48,
  DW_AT_type = 0x49,
  DW_AT_use_location = 0x4a,
  DW_AT_variable_parameter = 0x4b,
  DW_AT_virtuality = 0x4c,
  DW_AT_vtable_elem_location = 0x4d,
  DW_AT_allocated = 0x4e,
  DW_AT_associated = 0x4f,
  DW_AT_data_location = 0x50,
  DW_AT_byte_stride = 0x51,
  DW_AT_entry_pc = 0x52,
  DW_AT_use_UTF8 = 0x53,
  DW_AT_extension = 0x54,
  DW_AT_ranges = 0x55,
  DW_AT_trampoline = 0x56,
  DW_AT_call_column = 0x57,
  DW_AT_call_file = 0x58,
  DW_AT_call_line = 0x59,
  DW_AT_description = 0x5a,
  DW_AT_binary_scale = 0x5b,
  DW_AT_decimal_scale = 0x5c,
  DW_AT_small = 0x5d,
  DW_AT_decimal_sign = 0x5e,
  DW_AT_digit_count = 0x5f,
  DW_AT_picture_string = 0x60,
  DW_AT_mutable = 0x61,
  DW_AT_threads_scaled = 0x62,
  DW_AT_explicit = 0x63,
  DW_AT_object_pointer = 0x64,
  DW_AT_endianity = 0x65,
  DW_AT_elemental = 0x66,
  DW_AT_pure = 0x67,
  DW_AT_recursive = 0x68,
  DW_AT_signature = 0x69,
  DW_AT_main_subprogram = 0x6a,
  DW_AT_data_bit_offset = 0x6b,
  DW_AT_const_expr = 0x6c,
  DW_AT_enum_class = 0x6d,
  DW_AT_linkage_name = 0x6e,
  DW_AT_string_length_bit_size = 0x6f,
  DW_AT_string_length_byte_size = 0x70,
  DW_AT_rank = 0x71,
  DW_AT_str_offsets_base = 0x72,
  DW_AT_addr_base = 0x73,
  DW_AT_rnglists_base = 0x74,
  Reserved21 = 0x75,
  DW_AT_dwo_name = 0x76,
  DW_AT_reference = 0x77,
  DW_AT_rvalue_reference = 0x78,
  DW_AT_macros = 0x79,
  DW_AT_call_all_calls = 0x7a,
  DW_AT_call_all_source_calls = 0x7b,
  DW_AT_call_all_tail_calls = 0x7c,
  DW_AT_call_return_pc = 0x7d,
  DW_AT_call_value = 0x7e,
  DW_AT_call_origin = 0x7f,
  DW_AT_call_parameter = 0x80,
  DW_AT_call_pc = 0x81,
  DW_AT_call_tail_call = 0x82,
  DW_AT_call_target = 0x83,
  DW_AT_call_target_clobbered = 0x84,
  DW_AT_call_data_location = 0x85,
  DW_AT_call_data_value = 0x86,
  DW_AT_noreturn = 0x87,
  DW_AT_alignment = 0x88,
  DW_AT_export_symbols = 0x89,
  DW_AT_deleted = 0x8a,
  DW_AT_defaulted = 0x8b,
  DW_AT_loclists_base = 0x8c,
  DW_AT_lo_user = 0x2000,
  DW_AT_hi_user = 0x3fff,
};

enum class AttributeForm : std::uint8_t
{
  DW_FORM_addr = 0x01,            // 0b0000'0001
  Reserved = 0x02,                // 0b0000'0010
  DW_FORM_block2 = 0x03,          // 0b0000'0011
  DW_FORM_block4 = 0x04,          // 0b0000'0100
  DW_FORM_data2 = 0x05,           // 0b0000'0101
  DW_FORM_data4 = 0x06,           // 0b0000'0110
  DW_FORM_data8 = 0x07,           // 0b0000'0111
  DW_FORM_string = 0x08,          // 0b0000'1000
  DW_FORM_block = 0x09,           // 0b0000'1001
  DW_FORM_block1 = 0x0a,          // 0b0000'1010
  DW_FORM_data1 = 0x0b,           // 0b0000'1011
  DW_FORM_flag = 0x0c,            // 0b0000'1100
  DW_FORM_sdata = 0x0d,           // 0b0000'1101
  DW_FORM_strp = 0x0e,            // 0b0000'1110
  DW_FORM_udata = 0x0f,           // 0b0000'1111
  DW_FORM_ref_addr = 0x10,        // 0b0001'0001        ~( 0b0001'0111 ) -> 0b1110'1000
  DW_FORM_ref1 = 0x11,            // 0b0001'0010
  DW_FORM_ref2 = 0x12,            // 0b0001'0011
  DW_FORM_ref4 = 0x13,            // 0b0001'0100
  DW_FORM_ref8 = 0x14,            // 0b0001'0101
  DW_FORM_ref_udata = 0x15,       // 0b0001'0110
  DW_FORM_indirect = 0x16,        // 0b0001'0111
  DW_FORM_sec_offset = 0x17,      // 0b0001'1000
  DW_FORM_exprloc = 0x18,         // 0b0001'1001
  DW_FORM_flag_present = 0x19,    // 0b0001'1010
  DW_FORM_strx = 0x1a,            // 0b0001'1011
  DW_FORM_addrx = 0x1b,           // 0b0001'1100
  DW_FORM_ref_sup4 = 0x1c,        // 0b0001'1101
  DW_FORM_strp_sup = 0x1d,        // 0b0001'1110
  DW_FORM_data16 = 0x1e,          // 0b0001'1111
  DW_FORM_line_strp = 0x1f,       // 0b0000'0001
  DW_FORM_ref_sig8 = 0x20,        // 0b0000'0001
  DW_FORM_implicit_const = 0x21,  // 0b0000'0001
  DW_FORM_loclistx = 0x22,        // 0b0000'0001
  DW_FORM_rnglistx = 0x23,        // 0b0000'0001
  DW_FORM_ref_sup8 = 0x24,        // 0b0000'0001
  DW_FORM_strx1 = 0x25,           // 0b0000'0001
  DW_FORM_strx2 = 0x26,           // 0b0000'0001
  DW_FORM_strx3 = 0x27,           // 0b0000'0001
  DW_FORM_strx4 = 0x28,           // 0b0000'0001
  DW_FORM_addrx1 = 0x29,          // 0b0000'0001
  DW_FORM_addrx2 = 0x2a,          // 0b0000'0001
  DW_FORM_addrx3 = 0x2b,          // 0b0000'0001
  DW_FORM_addrx4 = 0x2c,          // 0b0000'0001
};

enum class BaseTypeAttributeEncoding : std::uint32_t
{
  DW_ATE_address = 0x01,
  DW_ATE_boolean = 0x02,
  DW_ATE_complex_float = 0x03,
  DW_ATE_float = 0x04,
  DW_ATE_signed = 0x05,
  DW_ATE_signed_char = 0x06,
  DW_ATE_unsigned = 0x07,
  DW_ATE_unsigned_char = 0x08,
  DW_ATE_imaginary_float = 0x09,
  DW_ATE_packed_decimal = 0x0a,
  DW_ATE_numeric_string = 0x0b,
  DW_ATE_edited = 0x0c,
  DW_ATE_signed_fixed = 0x0d,
  DW_ATE_unsigned_fixed = 0x0e,
  DW_ATE_decimal_float = 0x0f,
  DW_ATE_UTF = 0x10,
  DW_ATE_UCS = 0x11,
  DW_ATE_ASCII = 0x12,
  DW_ATE_lo_user = 0x80,
  DW_ATE_hi_user = 0xff,
};

enum class DecimalSignEncoding : std::uint32_t
{
  DW_DS_unsigned = 0x01,
  DW_DS_leading_overpunch = 0x02,
  DW_DS_trailing_overpunch = 0x03,
  DW_DS_leading_separate = 0x04,
  DW_DS_trailing_separate = 0x05,
};

enum class EndianityEncoding : std::uint32_t
{
  DW_END_default = 0x00,
  DW_END_big = 0x01,
  DW_END_little = 0x02,
  DW_END_lo_user = 0x40,
  DW_END_hi_user = 0xff,
};

enum class AccessibilityEncoding : std::uint32_t
{
  DW_ACCESS_public = 0x01,
  DW_ACCESS_protected = 0x02,
  DW_ACCESS_private = 0x03,
};

enum class VisibilityEncoding : std::uint32_t
{
  DW_VIS_local = 0x01,
  DW_VIS_exported = 0x02,
  DW_VIS_qualified = 0x03,
};

enum class VirtualityEncoding : std::uint32_t
{
  DW_VIRTUALITY_none = 0x00,
  DW_VIRTUALITY_virtual = 0x01,
  DW_VIRTUALITY_pure_virtual = 0x02,
};

enum class SourceLanguage : std::uint32_t
{
  DW_LANG_C89 = 0x0001,
  DW_LANG_C = 0x0002,
  DW_LANG_Ada83 = 0x0003,
  DW_LANG_C_plus_plus = 0x0004,
  DW_LANG_Cobol74 = 0x0005,
  DW_LANG_Cobol85 = 0x0006,
  DW_LANG_Fortran77 = 0x0007,
  DW_LANG_Fortran90 = 0x0008,
  DW_LANG_Pascal83 = 0x0009,
  DW_LANG_Modula2 = 0x000a,
  DW_LANG_Java = 0x000b,
  DW_LANG_C99 = 0x000c,
  DW_LANG_Ada95 = 0x000d,
  DW_LANG_Fortran95 = 0x000e,
  DW_LANG_PLI = 0x000f,
  DW_LANG_ObjC = 0x0010,
  DW_LANG_ObjC_plus_plus = 0x0011,
  DW_LANG_UPC = 0x0012,
  DW_LANG_D = 0x0013,
  DW_LANG_Python = 0x0014,
  DW_LANG_OpenCL = 0x0015,
  DW_LANG_Go = 0x0016,
  DW_LANG_Modula3 = 0x0017,
  DW_LANG_Haskell = 0x0018,
  DW_LANG_C_plus_plus_03 = 0x0019,
  DW_LANG_C_plus_plus_11 = 0x001a,
  DW_LANG_OCaml = 0x001b,
  DW_LANG_Rust = 0x001c,
  DW_LANG_C11 = 0x001d,
  DW_LANG_Swift = 0x001e,
  DW_LANG_Julia = 0x001f,
  DW_LANG_Dylan = 0x0020,
  DW_LANG_C_plus_plus_14 = 0x0021,
  DW_LANG_Fortran03 = 0x0022,
  DW_LANG_Fortran08 = 0x0023,
  DW_LANG_RenderScript = 0x0024,
  DW_LANG_BLISS = 0x0025,
  DW_LANG_lo_user = 0x8000,
  DW_LANG_hi_user = 0xffff,
};

enum class IdentifierCaseEncoding : std::uint32_t
{
  DW_ID_case_sensitive = 0x00,
  DW_ID_up_case = 0x01,
  DW_ID_down_case = 0x02,
  DW_ID_case_insensitive = 0x03,
};

enum class CallingConventionEncoding : std::uint32_t
{
  DW_CC_normal = 0x01,
  DW_CC_program = 0x02,
  DW_CC_nocall = 0x03,
  DW_CC_pass_by_reference = 0x04,
  DW_CC_pass_by_value = 0x05,
  DW_CC_lo_user = 0x40,
  DW_CC_hi_user = 0xff,
};

enum class InlineCodes : std::uint32_t
{
  DW_INL_not_inlined = 0x00,
  DW_INL_inlined = 0x01,
  DW_INL_declared_not_inlined = 0x02,
  DW_INL_declared_inlined = 0x03,
};

enum class ArrayOrdering : std::uint32_t
{
  DW_ORD_row_major = 0x00,
  DW_ORD_col_major = 0x01,
};

enum class DiscriminantList : std::uint32_t
{
  DW_DSC_label = 0x00,
  DW_DSC_range = 0x01,
};

enum class NameIndexTable : std::uint32_t
{
  DW_IDX_compile_unit = 1,
  DW_IDX_type_unit = 2,
  DW_IDX_die_offset = 3,
  DW_IDX_parent = 4,
  DW_IDX_type_hash = 5,
  DW_IDX_lo_user = 0x2000,
  DW_IDX_hi_user = 0x3fff,
};

enum class DefaultedMemberEncoding : std::uint32_t
{
  DW_DEFAULTED_no = 0x00,
  DW_DEFAULTED_in_class = 0x01,
  DW_DEFAULTED_out_of_class = 0x02,
};

enum class DwarfUnitType : std::uint8_t
{
  UNSUPPORTED,
  DW_UT_compile = 0x01,
  DW_UT_type = 0x02,
  DW_UT_partial = 0x03,
  DW_UT_skeleton = 0x04,
  DW_UT_split_compile = 0x05,
  DW_UT_split_type = 0x06,
  DW_UT_lo_user = 0x80,
  DW_UT_hi_user = 0xff,
};

enum class DwarfTag : std::uint16_t {
    DW_TAG_array_type = 0x01,
    DW_TAG_class_type = 0x02,
    DW_TAG_entry_point = 0x03,
    DW_TAG_enumeration_type = 0x04,
    DW_TAG_formal_parameter = 0x05,
    // Reserved0x6 = 0x06,
    // Reserved0x7 = 0x07,
    DW_TAG_imported_declaration = 0x08,
    // Reserved = 0x09,
    DW_TAG_label = 0x0a,
    DW_TAG_lexical_block = 0x0b,
    // Reserved = 0x0c,
    DW_TAG_member = 0x0d,
    // Reserved = 0x0e,
    DW_TAG_pointer_type = 0x0f,
    DW_TAG_reference_type = 0x10,
    DW_TAG_compile_unit = 0x11,
    DW_TAG_string_type = 0x12,
    DW_TAG_structure_type = 0x13,
    // Reserved = 0x14,
    DW_TAG_subroutine_type = 0x15,
    DW_TAG_typedef = 0x16,
    DW_TAG_union_type = 0x17,
    DW_TAG_unspecified_parameters = 0x18,
    DW_TAG_variant = 0x19,
    DW_TAG_common_block = 0x1a,
    DW_TAG_common_inclusion = 0x1b,
    DW_TAG_inheritance = 0x1c,
    DW_TAG_inlined_subroutine = 0x1d,
    DW_TAG_module = 0x1e,
    DW_TAG_ptr_to_member_type = 0x1f,
    DW_TAG_set_type = 0x20,
    DW_TAG_subrange_type = 0x21,
    DW_TAG_with_stmt = 0x22,
    DW_TAG_access_declaration = 0x23,
    DW_TAG_base_type = 0x24,
    DW_TAG_catch_block = 0x25,
    DW_TAG_const_type = 0x26,
    DW_TAG_constant = 0x27,
    DW_TAG_enumerator = 0x28,
    DW_TAG_file_type = 0x29,
    DW_TAG_friend = 0x2a,
    DW_TAG_namelist = 0x2b,
    DW_TAG_namelist_item = 0x2c,
    DW_TAG_packed_type = 0x2d,
    DW_TAG_subprogram = 0x2e,
    DW_TAG_template_type_parameter = 0x2f,
    DW_TAG_template_value_parameter = 0x30,
    DW_TAG_thrown_type = 0x31,
    DW_TAG_try_block = 0x32,
    DW_TAG_variant_part = 0x33,
    DW_TAG_variable = 0x34,
    DW_TAG_volatile_type = 0x35,
    DW_TAG_dwarf_procedure = 0x36,
    DW_TAG_restrict_type = 0x37,
    DW_TAG_interface_type = 0x38,
    DW_TAG_namespace = 0x39,
    DW_TAG_imported_module = 0x3a,
    DW_TAG_unspecified_type = 0x3b,
    DW_TAG_partial_unit = 0x3c,
    DW_TAG_imported_unit = 0x3d,
    // Reserved = 0x3e1,
    DW_TAG_condition = 0x3f,
    DW_TAG_shared_type = 0x40,
    DW_TAG_type_unit = 0x41,
    DW_TAG_rvalue_reference_type = 0x42,
    DW_TAG_template_alias = 0x43,
    DW_TAG_coarray_type = 0x44,        // ‡
    DW_TAG_generic_subrange = 0x45,    // ‡
    DW_TAG_dynamic_type = 0x46,        // ‡
    DW_TAG_atomic_type = 0x47,         // ‡
    DW_TAG_call_site = 0x48,           // ‡
    DW_TAG_call_site_parameter = 0x49, // ‡
    DW_TAG_skeleton_unit = 0x4a,       // ‡
    DW_TAG_immutable_type = 0x4b,      // ‡
    DW_TAG_lo_user = 0x4080,
    DW_TAG_hi_user = 0xffff,
};
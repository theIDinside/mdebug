#include "../../src/symbolication/dwarf_frameunwinder.h"
#include "../../src/symbolication/elf.h"
#include <algorithm>
#include <array>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <sys/user.h>
#include <type_traits>

//

// leak memory because who cares, it's a test
static ElfSection
create_mock_eh_frame_section()
{
  ScopedFd ehframe = ScopedFd::open("/home/cx/dev/foss/cx/dbm/test/unittest/threads_ehframe", O_RDONLY);
  EXPECT_EQ(ehframe.file_size(), 3716);

  auto ehframe_data = new std::vector<u8>{};
  ehframe_data->resize(ehframe.file_size());

  EXPECT_NE(::read(ehframe, ehframe_data->data(), ehframe.file_size()), -1);
  auto mock_eh_frame = ElfSection{.m_section_ptr = ehframe_data->data(),
                                  .m_name = ".eh_frame",
                                  .m_section_size = ehframe.file_size(),
                                  .file_offset = 0x3608,
                                  .address = 0x403608};

  return mock_eh_frame;
}

static ElfSection
create_ehframe(const char *path)
{
  ScopedFd ehframe = ScopedFd::open(path, O_RDONLY);

  auto ehframe_data = new std::vector<u8>{};
  ehframe_data->resize(ehframe.file_size());

  EXPECT_NE(::read(ehframe, ehframe_data->data(), ehframe.file_size()), -1);
  auto mock_eh_frame = ElfSection{.m_section_ptr = ehframe_data->data(),
                                  .m_name = ".eh_frame",
                                  .m_section_size = ehframe.file_size(),
                                  .file_offset = 0x325fce8,
                                  .address = 0x325fce8};

  return mock_eh_frame;
}

std::vector<u8>
create_mock_eh_frame_hdr_data()
{
  ScopedFd ehframe_header =
      ScopedFd::open("/home/cx/dev/foss/cx/dbm/test/unittest/threads_ehframe_header", O_RDONLY);
  EXPECT_EQ(ehframe_header.file_size(), 912);
  std::vector<u8> ehframe_header_data{};
  ehframe_header_data.resize(ehframe_header.file_size());
  EXPECT_NE(::read(ehframe_header, ehframe_header_data.data(), ehframe_header.file_size()), -1);
  return ehframe_header_data;
}

static const auto mock_eh_frame = create_mock_eh_frame_section();

constexpr static auto LIBXUL_EH_FRAME_FDE_COUNT = 417556;
constexpr static auto LIBXUL_DEBUG_FRAME_FDE_COUNT = 14788;
constexpr static auto LIBXUL_EH_FRAME_CIE_COUNT = 2;
constexpr static auto LIBXUL_DEBUG_FRAME_CIE_COUNT = 1835;
constexpr static auto LIBXUL_TOTAL_FDE = LIBXUL_EH_FRAME_FDE_COUNT + LIBXUL_DEBUG_FRAME_FDE_COUNT;
constexpr static auto LIBXUL_TOTAL_CIE = LIBXUL_EH_FRAME_CIE_COUNT + LIBXUL_DEBUG_FRAME_CIE_COUNT;
static const auto libxul_eh_frame = create_ehframe("/home/cx/dev/foss/cx/dbm/test/unittest/libxul_eh_frame");
static const auto libxul_debug_frame = create_ehframe("/home/cx/dev/foss/cx/dbm/test/unittest/libxul_debug_frame");
static const auto ehframe_header_data = create_mock_eh_frame_hdr_data();

TEST(CallFrameParsing, calculateCieFdeCount)
{
  const auto [cie_count, fde_count] =
      sym::elf_eh_calculate_entries_count(DwarfBinaryReader{mock_eh_frame.data(), mock_eh_frame.size()});
  EXPECT_EQ(cie_count, 2);
  EXPECT_EQ(fde_count, 112);
}

TEST(CallFrameParsing, calculateCieFdeCount_libxul)
{
  const auto [cie_count, fde_count] =
      sym::elf_eh_calculate_entries_count(DwarfBinaryReader{libxul_eh_frame.data(), libxul_eh_frame.size()});
  const auto [cie_count2, fde_count2] = sym::dwarf_eh_calculate_entries_count(
      DwarfBinaryReader{libxul_debug_frame.data(), libxul_debug_frame.size()});

  EXPECT_EQ(cie_count, LIBXUL_EH_FRAME_CIE_COUNT);
  EXPECT_EQ(fde_count, LIBXUL_EH_FRAME_FDE_COUNT);

  // correct parsing of .debug_frame not yet done, (but .eh_frame is correct!!!)
  EXPECT_EQ(cie_count2, LIBXUL_DEBUG_FRAME_CIE_COUNT);
  EXPECT_EQ(fde_count2, LIBXUL_DEBUG_FRAME_FDE_COUNT);
  EXPECT_EQ(cie_count + cie_count2, LIBXUL_EH_FRAME_CIE_COUNT + LIBXUL_DEBUG_FRAME_CIE_COUNT);
  EXPECT_EQ(fde_count + fde_count2, LIBXUL_EH_FRAME_FDE_COUNT + LIBXUL_DEBUG_FRAME_FDE_COUNT);
}

TEST(CallFrameParsing, parseLibxulUnwindInfo)
{
  auto unwinder = sym::parse_eh(nullptr, &libxul_eh_frame, -1);
  sym::parse_dwarf_eh(unwinder, &libxul_debug_frame, -1);
  EXPECT_EQ(LIBXUL_TOTAL_FDE, unwinder->total_fdes());
  EXPECT_EQ(LIBXUL_TOTAL_CIE, unwinder->total_cies());
}

TEST(CallFrameParsing, getRegisterValueByDwarfRegisterNumber)
{
  user_regs_struct regs{0};
  regs.rbp = 0xdeadbeef;
  regs.rsp = 0xba5;
  EXPECT_EQ(get_register(&regs, 6), 0xdeadbeef);
  EXPECT_EQ(get_register(&regs, 7), 0xba5);
}

TEST(CallFrameParsing, verifyParsedEhFrameInOrder)
{
  auto unwinder = sym::parse_eh(nullptr, &mock_eh_frame, -1);
  auto &entries = unwinder->elf_eh_unwind_infos;
  std::sort(entries.begin(), entries.end(), [](auto &a, auto &b) { return a.start < b.start; });
  auto start = entries.front().start;
  for (auto i = entries.begin() + 1; i != entries.end(); ++i) {
    EXPECT_GT(i->start, start);
  }
}

TEST(CallFrameParsing, parseThreadsShared)
{
  // const auto mock_eh_frame = create_mock_eh_frame_section();
  // const auto ehframe_header_data = create_mock_eh_frame_hdr_data();

  DwarfBinaryReader reader{mock_eh_frame.data(), mock_eh_frame.size()};
  sym::CIE cie = sym::read_cie(reader);
  EXPECT_EQ(cie.length, 0x14);
  EXPECT_EQ(cie.id, 0);
  EXPECT_EQ(cie.version, 1);
  EXPECT_EQ(cie.augmentation_string.value_or(""), "zR");
  EXPECT_EQ(cie.code_alignment_factor, 1);
  EXPECT_EQ(cie.data_alignment_factor, -8);
  EXPECT_EQ(cie.retaddr_register, 16);
  constexpr u8 values[7]{0x0C, 0x7, 0x8, 0x90, 0x1, 0x0, 0x0};
  auto expected_ins_bytestream = std::span{values};
  for (auto i = 0; i < 7; ++i) {
    EXPECT_EQ(cie.instructions[i], expected_ins_bytestream[i]);
  }
  EXPECT_EQ(reader.bytes_read(), 24);

  DwarfBinaryReader header_reader{ehframe_header_data.data(), ehframe_header_data.size()};
  auto header = sym::read_frame_header(header_reader);
  EXPECT_EQ(908, header.frame_ptr.u);
  EXPECT_EQ(112, header.fde_count.u);

  auto unwinder = sym::parse_eh(nullptr, &mock_eh_frame, -1);

  auto &entries = unwinder->elf_eh_unwind_infos;

  EXPECT_EQ(entries[0].start, AddrPtr{0x4011d0});
  EXPECT_EQ(entries[0].end, AddrPtr{0x4011f6});
  EXPECT_EQ(entries[0].cie->instructions.size(), 7);
  EXPECT_EQ(entries[0].fde_insts.size(), 3);

  EXPECT_EQ(entries[1].start, AddrPtr{0x401200});
  EXPECT_EQ(entries[1].end, AddrPtr{0x401205});
  EXPECT_EQ(entries[1].fde_insts.size(), 3);

  EXPECT_EQ(entries[2].start, AddrPtr{0x401020});
  EXPECT_EQ(entries[2].end, AddrPtr{0x401170});
  EXPECT_EQ(entries[2].fde_insts.size(), 23);

  EXPECT_EQ(entries[3].start, AddrPtr{0x401170});
  EXPECT_EQ(entries[3].end, AddrPtr{0x4011c0});
  EXPECT_EQ(entries[3].fde_insts.size(), 15);
  EXPECT_EQ(entries[3].fde_insts.back(), 0);
  EXPECT_EQ(entries[3].fde_insts[entries[3].fde_insts.size() - 2], 0);

  EXPECT_EQ(entries[entries.size() - 1].cie, &unwinder->elf_eh_cies.back());
  EXPECT_EQ(entries[entries.size() - 2].cie, &unwinder->elf_eh_cies.front());
  EXPECT_EQ(entries[entries.size() - 7].cie, &unwinder->elf_eh_cies.back());

  sym::ByteCodeInterpreter cie_interp{entries[0].cie->instructions};
  auto cie_debug = cie_interp.debug_parse();
  EXPECT_EQ(cie_debug.size(), 4);
  sym::ByteCodeInterpreter fde_interp{entries[0].fde_insts};
  auto fde_debug = fde_interp.debug_parse();
  EXPECT_EQ(fde_debug.size(), 2);
  using I = DwarfCallFrame;
  constexpr DwarfCallFrame cie_names[4] = {I::DW_CFA_def_cfa, I::DW_CFA_offset, I::DW_CFA_nop, I::DW_CFA_nop};
  constexpr DwarfCallFrame fde_names[2] = {I::DW_CFA_advance_loc, I::DW_CFA_undefined};

  for (auto i = 0; i < 4; i++) {
    EXPECT_EQ(cie_debug[i], cie_names[i]);
    EXPECT_EQ(to_str(cie_debug[i]), to_str(cie_names[i]));
  }

  for (auto i = 0; i < 2; i++) {
    EXPECT_EQ(fde_debug[i], fde_names[i]);
    EXPECT_EQ(to_str(fde_debug[i]), to_str(fde_names[i]));
  }

  constexpr DwarfCallFrame fde3[]{
      I::DW_CFA_def_cfa_offset,
      I::DW_CFA_advance_loc,
      I::DW_CFA_def_cfa_offset,
      I::DW_CFA_advance_loc,
      I::DW_CFA_def_cfa_expression,
      I::DW_CFA_nop,
      I::DW_CFA_nop,
      I::DW_CFA_nop,
      I::DW_CFA_nop,
  };

  sym::ByteCodeInterpreter fde3_interp{entries[2].fde_insts};
  auto fde3_debug = fde3_interp.debug_parse();
  EXPECT_EQ(fde3_debug.size(), sizeof(fde3));
  for (auto i = 0u; i < fde3_debug.size(); ++i) {
    EXPECT_EQ(fde3_debug[i], fde3[i]);
    EXPECT_EQ(to_str(fde3_debug[i]), to_str(fde3[i]));
    std::cout << to_str(fde3_debug[i]) << std::endl;
  }
}
#pragma once
#include "arch.h"
#include <map>
#include <optional>
#include <string>
#include <typedefs.h>
#include <vector>

namespace xml {
struct XMLElementView;
};

// Code explicitly created to handle GDB (for all it's awesomeness and horridness).
namespace gdb {

struct ArchReg
{
  std::string_view name;
  std::string_view type;
  u16 bit_size;
  u16 regnum;
};

struct ArchictectureInfo
{
  std::vector<ArchReg> registers{};
  ArchType type{ArchType::X86_64};
  u32 register_block_size{816};
  u32 pc_number{16};
  u32 register_bytes() const noexcept;
};

std::vector<gdb::ArchReg> read_arch_info(const xml::XMLElementView &root) noexcept;

} // namespace gdb
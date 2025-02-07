/** LICENSE TEMPLATE */
#pragma once
#include "utils/immutable.h"
#include <typedefs.h>
#include <vector>

namespace mdb::xml {
struct XMLElementView;
};

// Code explicitly created to handle GDB (for all it's awesomeness and horridness).
namespace mdb::gdb {

struct ArchReg
{
  std::string name;
  std::string type;
  u16 bit_size;
  u16 regnum;
};

struct DebuggerContextRegisters
{
  Immutable<u16> mRIPOffset;
  Immutable<u8> mRIPNumber;
  Immutable<u16> mRSPOffset;
  Immutable<u8> mRSPNumber;
  Immutable<u16> mRBPOffset;
  Immutable<u8> mRBPNumber;
};

struct RegisterName
{
  std::string name;
  std::string type;
};

struct RegisterMetadata
{
  u16 bit_size;
  u16 mOffset;
};

struct RegisterInfo
{
  Immutable<std::vector<RegisterMetadata>> mRegisterMetaData;
  Immutable<std::vector<RegisterName>> mRegisterNames;
};

struct ArchictectureInfo
{
  Immutable<RegisterInfo> mRegisters;
  Immutable<DebuggerContextRegisters> mDebugContextRegisters;

  ArchictectureInfo(RegisterInfo &&registers, const DebuggerContextRegisters &debugRegisters) noexcept;
  static std::shared_ptr<ArchictectureInfo> CreateArchInfo(const std::vector<ArchReg> &registers);
  u32 register_bytes() const noexcept;
};

std::vector<gdb::ArchReg> read_arch_info(const xml::XMLElementView &root, int *registerNumber) noexcept;

} // namespace mdb::gdb
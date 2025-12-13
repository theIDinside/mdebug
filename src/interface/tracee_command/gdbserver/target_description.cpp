/** LICENSE TEMPLATE */
#include "target_description.h"
#include "utils/util.h"
#include "utils/xml.h"
#include <common.h>

namespace mdb::gdb {

std::vector<ArchReg>
read_arch_info(const xml::XMLElementView &root, int *registerNumber) noexcept
{
  std::vector<gdb::ArchReg> result{};
  result.reserve(85);
  // we do this for simplicity's sake, not for perfance. We do this once per target or session
  // and it's literally a sub-second operation in total.
  auto regs = xml::collect_by_name(root, "reg", false);

  for (const auto reg : regs) {
    auto &r = result.emplace_back();
    for (const auto &[k, v] : reg->attributes) {
      if (k == "name") {
        r.name = v;
      } else if (k == "bitsize") {
        const auto res = std::from_chars(v.data(), v.data() + v.size(), r.bit_size);
        MDB_ASSERT(res.ec == std::errc(), "Failed to parse bit size from target description for register");
      } else if (k == "type") {
        r.type = v;
      } else if (k == "regnum") {
        const auto res = std::from_chars(v.data(), v.data() + v.size(), r.regnum);
        MDB_ASSERT(res.ec == std::errc(), "Failed to parse reg num from target description for register");
        MDB_ASSERT(r.regnum == *registerNumber, "Target description is no longer contiguous.");
      }
    }
    if (r.regnum == 0) {
      r.regnum = *registerNumber;
    }
    (*registerNumber) += 1;

    // Debugger-Context Registers. I like my own name for these registers. Because they're the debug context; the
    // stack, the pc and the current stack frame (if available)
  }
  mdb::sort(result, [](const auto &a, const auto &b) { return a.regnum < b.regnum; });
  return result;
}

/*static*/
std::shared_ptr<ArchictectureInfo>
ArchictectureInfo::CreateArchInfo(const std::vector<ArchReg> &registers)
{
  std::vector<RegisterMetadata> metaData;
  std::vector<RegisterName> regNames;
  u16 byteOffset = 0u;

  u16 mRIPOffset;
  u8 mRIPNumber;
  u16 mRSPOffset;
  u8 mRSPNumber;
  u16 mRBPOffset;
  u8 mRBPNumber;

  auto registerNumber = 0u;
  for (const auto &r : registers) {
    metaData.push_back({ r.bit_size, byteOffset });
    if (r.name == "rip") {
      mRIPOffset = byteOffset;
      mRIPNumber = registerNumber;
    } else if (r.name == "rsp") {
      mRSPOffset = byteOffset;
      mRSPNumber = registerNumber;
    } else if (r.name == "rbp") {
      mRBPOffset = byteOffset;
      mRBPNumber = registerNumber;
    }
    regNames.push_back({ r.name, r.type });
    byteOffset += (r.bit_size / 8);
    registerNumber += 1;
  }
  return std::make_shared<ArchictectureInfo>(RegisterInfo{ std::move(metaData), std::move(regNames) },
    DebuggerContextRegisters{ mRIPOffset, mRIPNumber, mRSPOffset, mRSPNumber, mRBPOffset, mRBPNumber });
}

ArchictectureInfo::ArchictectureInfo(
  RegisterInfo &&registers, const DebuggerContextRegisters &debugRegisters) noexcept
    : mRegisters(std::move(registers)), mDebugContextRegisters(debugRegisters)
{
}

u32
ArchictectureInfo::register_bytes() const noexcept
{
  return mdb::accumulate(
    mRegisters->mRegisterMetaData, [](u32 acc, auto &reg) -> u32 { return acc + (reg.bit_size / 8); });
}

} // namespace mdb::gdb
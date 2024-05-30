#include "target_description.h"
#include "utils/util.h"
#include "utils/xml.h"
#include <common.h>

namespace gdb {

std::vector<gdb::ArchReg>
read_arch_info(const xml::XMLElementView &root) noexcept
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
        ASSERT(res.ec == std::errc(), "Failed to parse bit size from target description for register");
      } else if (k == "type") {
        r.type = v;
      } else if (k == "regnum") {
        const auto res = std::from_chars(v.data(), v.data() + v.size(), r.regnum);
        ASSERT(res.ec == std::errc(), "Failed to parse reg num from target description for register");
      }
    }
  }
  utils::sort(result, [](const auto &a, const auto &b) { return a.regnum < b.regnum; });
  return result;
}

u32
ArchictectureInfo::register_bytes() const noexcept
{
  return utils::accumulate(registers, [](u32 acc, auto &reg) -> u32 { return acc + (reg.bit_size / 8); });
}

} // namespace gdb
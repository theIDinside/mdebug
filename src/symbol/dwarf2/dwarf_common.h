#pragma once
#include <common.h>

namespace sym::dw2 {
class DwarfId
{
public:
  explicit DwarfId(u64 uid) noexcept;

  u64 get_id() const noexcept;

  bool operator<(const DwarfId &other) noexcept;
  bool operator==(const DwarfId &other) noexcept;
  bool operator>(const DwarfId &other) noexcept;

private:
  u64 uid;
};
}; // namespace sym::dw2
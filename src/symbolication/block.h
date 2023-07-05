#pragma once
#include "../src/common.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct AddressRange
{
  TPtr<void> low;
  TPtr<void> high;
  bool contains(AddressRange &range) const noexcept;
  bool contains(TPtr<void> ptr) const noexcept;
  bool is_valid() const noexcept;
};

class AddrRanges
{
  u64 m_block_count;
  AddressRange *m_blocks;

public:
  AddrRanges(AddressRange *blocks, u64 block_count) noexcept;
  std::span<AddressRange> blocks() const noexcept;
};
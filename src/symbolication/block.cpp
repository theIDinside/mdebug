#include "block.h"

AddrRanges::AddrRanges(AddressRange *blocks, u64 block_count) noexcept
    : m_block_count(block_count), m_blocks(blocks)
{
}

std::span<AddressRange>
AddrRanges::blocks() const noexcept
{
  return std::span{m_blocks, m_block_count};
}

bool
AddressRange::contains(AddressRange &block) const noexcept
{
  return block.low.get() >= low.get() && block.high.get() <= high.get();
}

bool
AddressRange::contains(TPtr<void> ptr) const noexcept
{
  return ptr.get() >= low.get() && ptr.get() <= high.get();
}

bool
AddressRange::is_valid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}
#include "block.h"

AddrRanges::AddrRanges(Block *blocks, u64 block_count) noexcept : m_block_count(block_count), m_blocks(blocks) {}

std::span<Block>
AddrRanges::blocks() const noexcept
{
  return std::span{m_blocks, m_block_count};
}

bool
Block::contains(Block &block) const noexcept
{
  return block.low.get() >= low.get() && block.high.get() <= high.get();
}

bool
Block::contains(TPtr<void> ptr) const noexcept
{
  return ptr.get() >= low.get() && ptr.get() <= high.get();
}

bool
Block::is_valid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}
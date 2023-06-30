#include "block.h"

AddrRanges::AddrRanges(Block *blocks, u64 block_count) noexcept : m_block_count(block_count), m_blocks(blocks) {}

std::span<Block>
AddrRanges::blocks() const noexcept
{
  return std::span{m_blocks, m_block_count};
}

bool Block::contains(Block &block) const noexcept {
  return block.low.get() >= low.get() && block.high.get() <= high.get();
}
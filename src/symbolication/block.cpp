#include "block.h"

AddrRanges::AddrRanges(Block *blocks, u64 block_count) noexcept : m_block_count(block_count), m_blocks(blocks) {}

std::span<Block>
AddrRanges::blocks() const noexcept
{
  return std::span{m_blocks, m_block_count};
}
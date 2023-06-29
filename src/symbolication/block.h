#pragma once
#include "../src/common.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct Block
{
  TPtr<void> start;
  TPtr<void> exclusive_end;
};

class AddrRanges
{
  u64 m_block_count;
  Block *m_blocks;

public:
  AddrRanges(Block *blocks, u64 block_count) noexcept;
  std::span<Block> blocks() const noexcept;
};
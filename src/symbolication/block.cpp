#include "block.h"

bool
AddressRange::contains(AddressRange &block) const noexcept
{
  return block.low >= low && block.high <= high;
}

bool
AddressRange::contains(AddrPtr ptr) const noexcept
{
  return ptr >= low && ptr < high;
}

bool
AddressRange::is_valid() const noexcept
{
  return low != TPtr<void>{nullptr} && high != TPtr<void>{nullptr};
}

namespace sym {

Block::Block(AddrPtr start, AddrPtr end) noexcept : pc_start(start), pc_end_exclusive(end) {}

AddrPtr
Block::start_pc() const noexcept
{
  return pc_start;
}

AddrPtr
Block::end_pc() const noexcept
{
  return pc_end_exclusive;
}

Block *
Block::containing_block() const noexcept
{
  return contained_in;
}

void
Block::set_contained_by(Block *block) noexcept
{
  contained_in = block;
}

const Block *
BlockArray::block_from_pc(AddrPtr pc) noexcept
{
  // TODO(simon): Don't do linear searches here.
  for (const auto &b : blocks) {
    if (b.start_pc() <= pc && b.end_pc() >= pc)
      return &b;
  }
  return nullptr;
}

AddrPtr
BlockArray::start_pc() const noexcept
{
  return pc_start;
}

AddrPtr
BlockArray::end_pc() const noexcept
{
  return pc_end_exclusive;
}

} // namespace sym
#pragma once
#include "../common.h"
#include "addr_sorter.h"
#include "dwarf/common.h"

/**
 * Description of a range of executable code, inside of a compilation unit.
 */
struct AddressRange
{
  AddrPtr low;
  AddrPtr high;

  // useful when we want to iteratively find low and high
  static constexpr AddressRange
  MaxMin() noexcept
  {
    return AddressRange{AddrPtr::Max(), AddrPtr::Min()};
  }
  bool contains(AddressRange &range) const noexcept;
  bool contains(AddrPtr ptr) const noexcept;
  bool is_valid() const noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;

  constexpr static auto
  Sorter()
  {
    return AddressableSorter<AddressRange, true>{};
  }
};

class BoundsBuilder
{
private:
  u64 low = UINTMAX_MAX;
  u64 high = 0;

public:
  bool
  next(u64 l, u64 h) noexcept
  {
    if (l == 0 && h == 0)
      return false;
    low = std::min(l, low);
    high = std::max(h, high);
    return true;
  }

  AddressRange
  done(AddrPtr relocate_base) const noexcept
  {
    return AddressRange{relocate_base + low, relocate_base + high};
  }

  constexpr bool
  valid() const noexcept
  {
    return low != UINTMAX_MAX && high != 0;
  }
};

namespace sym {
enum class BlockType
{
  Unit,
  Function,
  Lexical
};

class Block
{
  AddrPtr pc_start;
  AddrPtr pc_end_exclusive;
  Block *contained_in;
  SymbolInfoId containing_sym_info;

public:
  Block(AddrPtr start, AddrPtr end) noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
  Block *containing_block() const noexcept;
  void set_contained_by(Block *block) noexcept;
  void set_containing_sym_info(SymbolInfoId info) noexcept;

  static constexpr auto
  Sort()
  {
    return AddressableSorter<Block, true>{};
  }
};

class BlockArray
{
  AddrPtr pc_start;
  AddrPtr pc_end_exclusive;
  std::vector<Block> blocks;

  static constexpr auto
  Sort()
  {
    return AddressableSorter<BlockArray, false>{};
  }

public:
  BlockArray(AddrPtr start, AddrPtr end_exclusive) noexcept;
  const Block *block_from_pc(AddrPtr pc) noexcept;
  AddrPtr start_pc() const noexcept;
  AddrPtr end_pc() const noexcept;
};
} // namespace sym
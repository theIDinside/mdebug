#pragma once

#include <compare>
namespace sym::dw {
class UnitData;
struct DieMetaData;
struct DieReference;
struct IndexedDieReference;

class DieSiblingIterator
{
  UnitData *cu;
  const DieMetaData *die;

public:
  DieSiblingIterator(UnitData *cu, const DieMetaData *die) noexcept;
  DieSiblingIterator &operator++() noexcept;
  DieSiblingIterator operator++(int) noexcept;
  const DieMetaData &operator*() const noexcept;
  const DieMetaData *operator->() const noexcept;
  const DieMetaData &operator*() noexcept;
  const DieMetaData *operator->() noexcept;

  friend constexpr auto
  operator<=>(const DieSiblingIterator &l, const DieSiblingIterator &r) noexcept
  {
    auto res = l.cu <=> r.cu;
    if (res == std::strong_ordering::equal) {
      return l.die <=> r.die;
    } else {
      return res;
    }
  }

  friend constexpr auto
  operator!=(const DieSiblingIterator &l, const DieSiblingIterator &r) noexcept
  {
    auto res = l <=> r;
    return res != std::strong_ordering::equal;
  }

  static const DieMetaData *StartDie(const DieMetaData *die) noexcept;
};

class IterateSiblings
{
  UnitData *cu;
  const DieMetaData *die;

public:
  IterateSiblings(UnitData *cu, const DieMetaData *die) noexcept : cu(cu), die(die) {}

  auto
  begin() noexcept
  {
    return DieSiblingIterator{cu, die};
  }

  auto
  end() noexcept
  {
    return DieSiblingIterator{cu, nullptr};
  }

  auto
  cbegin() const noexcept
  {
    return DieSiblingIterator{cu, die};
  }

  auto
  cend() const noexcept
  {
    return DieSiblingIterator{cu, nullptr};
  }
};
} // namespace sym::dw
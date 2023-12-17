#pragma once
#include <common.h>

template <typename AddressContainingType>
concept Addressable = requires(AddressContainingType t) {
  // clang-format off
  { t.start_pc() } -> std::convertible_to<AddrPtr>;
  { t.end_pc() } -> std::convertible_to<AddrPtr>;
  // clang-format on
};

template <Addressable T, bool ByDecreasingEnd> class AddressableSorter
{
public:
  constexpr bool
  operator()(const T &a, const T &b) const noexcept
  {
    if constexpr (ByDecreasingEnd) {
      if (a.start_pc() == b.start_pc()) {
        return b.end_pc() > a.end_pc();
      } else {
        return a.start_pc() < b.start_pc();
      }
    } else {
      if (a.start_pc() == b.start_pc()) {
        return b.end_pc() < a.end_pc();
      } else {
        return a.start_pc() < b.start_pc();
      }
    }
  }

  constexpr bool
  operator()(const T *a, const T *b) const noexcept
  {
    return this->operator()(*a, *b);
  }
};

template <Addressable T> class AddressableLowBoundSorter
{
public:
  constexpr bool
  operator()(const T &a, const T &b) const noexcept
  {
    return a.start_pc() < b.start_pc();
  }

  constexpr bool
  operator()(const T *a, const T *b) const noexcept
  {
    return this->operator()(*a, *b);
  }
};

template <Addressable T>
constexpr auto
contained_in(const T &t, AddrPtr pc) noexcept -> bool
{
  return t.start_pc() <= pc && t.end_pc() >= pc;
}
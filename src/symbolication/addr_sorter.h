#pragma once

#include "tracee_pointer.h"
#include <concepts>

template <typename AddressContainingType>
concept Addressable = requires(AddressContainingType t) {
  // clang-format off
  { t.StartPc() } -> std::convertible_to<AddrPtr>;
  { t.EndPc() } -> std::convertible_to<AddrPtr>;
  // clang-format on
};

template <Addressable T, bool ByDecreasingEnd=false> class AddressableSorter
{
public:
  constexpr bool
  operator()(const T &a, const T &b) const noexcept
  {
    if constexpr (ByDecreasingEnd) {
      if (a.StartPc() == b.StartPc()) {
        return b.EndPc() > a.EndPc();
      } else {
        return a.StartPc() < b.StartPc();
      }
    } else {
      if (a.StartPc() == b.StartPc()) {
        return b.EndPc() < a.EndPc();
      } else {
        return a.StartPc() < b.StartPc();
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
    return a.StartPc() < b.StartPc();
  }

  constexpr bool
  operator()(const T *a, const T *b) const noexcept
  {
    return this->operator()(*a, *b);
  }
};

template <Addressable T> using SortLowPc = AddressableLowBoundSorter<T>;

template <Addressable T>
constexpr auto
contained_in(const T &t, AddrPtr pc) noexcept -> bool
{
  return t.StartPc() <= pc && t.EndPc() >= pc;
}
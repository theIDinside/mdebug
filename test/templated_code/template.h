#pragma once
#include <cstdio>

// Some different templated code, so that MDB can witness it's different effects, depending on
// what translation unit it's in, or what auto parameters do, constexpr, constexpr inline etc.
template <typename T>
T
less_than(const T &l, const T &r)
{
  const auto test = l < r; // BP1
  if (test) {
    return l;
  } else {
    return r;
  }
}

constexpr auto
greater_than(const auto &l, const auto &r)
{
  const auto test = l > r; // BP2
  if (test) {
    return l;
  } else {
    return r;
  }
}

template <typename T>
constexpr inline T
equals(const T &l, const T &r)
{
  const auto test = l == r; // BP3
  if (test) {
    return l;
  } else {
    return r;
  }
}

template <typename T> struct TemplateType
{
  T a, b;

  explicit TemplateType(T same) noexcept : a(same), b(same)
  {
    std::printf("constructing a TemplateType<T> in constructor\n"); // CTOR1
  }
  explicit TemplateType(T a, T b) noexcept : a(a), b(b)
  {
    std::printf("constructing a TemplateType<T> in constructor\n"); // CTOR2
  }
};
/** LICENSE TEMPLATE */
#pragma once
#include "utils/macros.h"
#include <utility>

template <typename DeferFn> class ScopedDefer
{
public:
  MOVE_ONLY(ScopedDefer);
  explicit ScopedDefer(DeferFn &&fn) noexcept : defer_fn(std::move(fn)) {}
  ~ScopedDefer() noexcept { defer_fn(); }

  ScopedDefer(ScopedDefer &&other) noexcept : defer_fn(std::move(other.defer_fn)) {}
  ScopedDefer &
  operator=(ScopedDefer &&other) noexcept
  {
    if (this != &other) {
      defer_fn = std::move(other.defer_fn);
    }
    return *this;
  }

private:
  DeferFn defer_fn;
};
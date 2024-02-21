#pragma once
#include <utility>

template <typename DeferFn> class ScopedDefer
{
public:
  explicit ScopedDefer(DeferFn &&fn) noexcept : defer_fn(std::move(fn)) {}
  ~ScopedDefer() noexcept { defer_fn(); }

private:
  DeferFn defer_fn;
};
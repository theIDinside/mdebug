#pragma once
#include <utility>

#if defined(__clang__)
#define MIDAS_UNREACHABLE std::unreachable();
#elif defined(__GNUC__) || defined(__GNUG__)
#define MIDAS_UNREACHABLE __builtin_unreachable();
#endif

#define NEVER(msg)                                                                                                \
  PANIC(msg);                                                                                                     \
  MIDAS_UNREACHABLE

#ifndef USING_SMART_PTRS
#define USING_SMART_PTRS(CLASS)                                                                                   \
  using OwnPtr = std::unique_ptr<CLASS>;                                                                          \
  using ShrPtr = std::shared_ptr<CLASS>;
#endif

#ifndef NO_COPY
/// Types that use NO_COPY in this codebase tend to be created and used via pointers, both raw and smart alike
/// Therefore also define OwnPtr and ShrPtr shortcuts.
#define NO_COPY(CLASS)                                                                                            \
  CLASS(const CLASS &) = delete;                                                                                  \
  CLASS(CLASS &) = delete;                                                                                        \
  CLASS &operator=(CLASS &) = delete;                                                                             \
  CLASS &operator=(const CLASS &) = delete;                                                                       \
  USING_SMART_PTRS(CLASS)
#endif

#ifndef MOVE_ONLY
#define MOVE_ONLY(CLASS)                                                                                          \
  CLASS(const CLASS &) = delete;                                                                                  \
  CLASS(CLASS &) = delete;                                                                                        \
  CLASS &operator=(CLASS &) = delete;                                                                             \
  CLASS &operator=(const CLASS &) = delete;
#endif

#ifndef NO_NON_EXPLICIT_CTORS
#define NO_NON_EXPLICIT_CTORS(CLASS)                                                                              \
  NO_COPY(CLASS)                                                                                                  \
  CLASS() noexcept = delete;                                                                                      \
  CLASS(CLASS &&) noexcept = delete;                                                                              \
  CLASS &operator=(CLASS &&) noexcept = delete;
#endif

#ifndef NO_COPY_DEFAULTED_MOVE
#define NO_COPY_DEFAULTED_MOVE(CLASS)                                                                             \
  NO_COPY(CLASS)                                                                                                  \
  CLASS(CLASS &&) noexcept = default;                                                                             \
  CLASS &operator=(CLASS &&) noexcept = default;
#endif
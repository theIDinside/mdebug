/** LICENSE TEMPLATE */
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

#ifndef NO_COPY
/// Types that use NO_COPY in this codebase tend to be created and used via pointers, both raw and smart alike
/// Therefore also define OwnPtr and ShrPtr shortcuts.
#define NO_COPY(CLASS)                                                                                            \
  CLASS(const CLASS &) = delete;                                                                                  \
  CLASS(CLASS &) = delete;                                                                                        \
  CLASS &operator=(CLASS &) = delete;                                                                             \
  CLASS &operator=(const CLASS &) = delete;
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

// Useful for "variant" types, where a default construction is *never* valid state.
#ifndef DELETED_DEFAULT_CTOR_DEFAULTED_COPY_MOVE
#define DELETED_DEFAULT_CTOR_DEFAULTED_COPY_MOVE(CLASS)                                                           \
  CLASS() noexcept = delete;                                                                                      \
  CLASS(const CLASS &) noexcept = default;                                                                        \
  CLASS &operator=(const CLASS &) noexcept = default;                                                             \
  CLASS(CLASS &&) noexcept = default;                                                                             \
  CLASS &operator=(CLASS &&) noexcept = default;
#endif

#define UnionVariant(TYPE) Immutable<TYPE> u##TYPE

#define UnionVariantConstructor(SUPER_TYPE, VARIANT_TYPE)                                                         \
  constexpr SUPER_TYPE(VARIANT_TYPE variant) noexcept                                                             \
      : mType(SUPER_TYPE##Discriminant::VARIANT_TYPE), u##VARIANT_TYPE(variant)                                   \
  {                                                                                                               \
  }
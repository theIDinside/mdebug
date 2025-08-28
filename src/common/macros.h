/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/typedefs.h>
#include <utils/util.h>

// stdlib
#include <optional>

#if defined(__clang__)
#define MIDAS_UNREACHABLE std::unreachable();
#elif defined(__GNUC__) || defined(__GNUG__)
#define MIDAS_UNREACHABLE __builtin_unreachable();
#endif

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

#define DEFAULT_ENUM(Value, ...) Value,

#define STRINGIFY_VAL(x, ...) #x,

#define CAST_FN(Value, ...)                                                                                       \
  case static_cast<i32>(Value):                                                                                   \
    return Value;

template <typename T> struct Enum
{
  static constexpr u32 Count() noexcept;
  static constexpr std::optional<T> FromInt(int value) noexcept;
};

#define ENUM_FMT(ENUM_TYPE, FOR_EACH_FN, CASE_FN)                                                                 \
  template <> struct std::formatter<ENUM_TYPE> : public Default<ENUM_TYPE>                                        \
  {                                                                                                               \
    template <typename FormatContext>                                                                             \
    auto                                                                                                          \
    format(const ENUM_TYPE &value, FormatContext &ctx) const                                                      \
    {                                                                                                             \
      return std::format_to(ctx.out(), "{}", Enum<ENUM_TYPE>::ToString(value));                                   \
    }                                                                                                             \
  }

// Using this macro instead of `ENUM_TYPE_METADATA` we can define values outside of the "public" range
// which are not intended for "automatic" use, but very niche (like setting exact range, or storing extra metadata)
#define PREDEFINED_ENUM_TYPE_METADATA(ENUM_TYPE, FOR_EACH, EACH_FN)                                               \
  namespace detail {                                                                                              \
  using enum ENUM_TYPE;                                                                                           \
  static constexpr auto ENUM_TYPE##Ids = std::to_array<ENUM_TYPE>({ FOR_EACH(DEFAULT_ENUM) });                    \
  static constexpr auto ENUM_TYPE##Names = std::to_array<std::string_view>({ FOR_EACH(STRINGIFY_VAL) });          \
  }                                                                                                               \
  template <> struct Enum<ENUM_TYPE>                                                                              \
  {                                                                                                               \
    static consteval auto                                                                                         \
    EnumBaseOffset() noexcept                                                                                     \
    {                                                                                                             \
      using enum ENUM_TYPE;                                                                                       \
      return std::to_underlying(detail::ENUM_TYPE##Ids[0]);                                                       \
    }                                                                                                             \
                                                                                                                  \
    static constexpr u32                                                                                          \
    Count() noexcept                                                                                              \
    {                                                                                                             \
      return detail::ENUM_TYPE##Ids.size();                                                                       \
    }                                                                                                             \
                                                                                                                  \
    static constexpr std::optional<ENUM_TYPE>                                                                     \
    FromInt(auto value) noexcept                                                                                  \
    {                                                                                                             \
      using enum ENUM_TYPE;                                                                                       \
      if (value < std::to_underlying(detail::ENUM_TYPE##Ids.front()) ||                                           \
          value > std::to_underlying(detail::ENUM_TYPE##Ids.back())) {                                            \
        return std::nullopt;                                                                                      \
      }                                                                                                           \
      switch (value) {                                                                                            \
        FOR_EACH(CAST_FN)                                                                                         \
      default:                                                                                                    \
        return std::nullopt;                                                                                      \
      }                                                                                                           \
      MIDAS_UNREACHABLE                                                                                           \
    }                                                                                                             \
                                                                                                                  \
    static constexpr std::span<const ENUM_TYPE>                                                                   \
    Variants()                                                                                                    \
    {                                                                                                             \
      return std::span{ detail::ENUM_TYPE##Ids };                                                                 \
    }                                                                                                             \
                                                                                                                  \
    static constexpr std::string_view                                                                             \
    ToString(ENUM_TYPE value) noexcept                                                                            \
    {                                                                                                             \
      static constexpr auto INDEX_OFFSET = EnumBaseOffset();                                                      \
      return detail::ENUM_TYPE##Names[std::to_underlying(value) - INDEX_OFFSET];                                  \
    }                                                                                                             \
                                                                                                                  \
    static constexpr std::span<const std::string_view>                                                            \
    Names() noexcept                                                                                              \
    {                                                                                                             \
      return std::span{ detail::ENUM_TYPE##Names };                                                               \
    }                                                                                                             \
    static constexpr std::optional<ENUM_TYPE>                                                                     \
    FromString(std::string_view str) noexcept                                                                     \
    {                                                                                                             \
      auto index = 0;                                                                                             \
      for (const auto &n : Names()) {                                                                             \
        if (n == str)                                                                                             \
          return detail::ENUM_TYPE##Ids[index];                                                                   \
        ++index;                                                                                                  \
      }                                                                                                           \
      return {};                                                                                                  \
    }                                                                                                             \
  };                                                                                                              \
  template <ENUM_TYPE EVENT> struct ENUM_TYPE##Traits;                                                            \
  ENUM_FMT(ENUM_TYPE, FOR_EACH, EACH_FN);

#define ENUM_TYPE_METADATA(ENUM_TYPE, FOR_EACH, EACH_FN, UNDERLYING_TYPE)                                         \
  enum class ENUM_TYPE : UNDERLYING_TYPE                                                                          \
  {                                                                                                               \
    FOR_EACH(EACH_FN)                                                                                             \
  };                                                                                                              \
  PREDEFINED_ENUM_TYPE_METADATA(ENUM_TYPE, FOR_EACH, EACH_FN)

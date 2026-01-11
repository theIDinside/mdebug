/** LICENSE TEMPLATE */
#pragma once

// std
#include <memory>
#include <type_traits>

namespace mdb {

template <typename, typename = void> struct has_begin : std::false_type
{
};

template <typename T> struct has_begin<T, std::void_t<decltype(std::begin(std::declval<T>()))>> : std::true_type
{
};

template <typename, typename = void> struct has_end : std::false_type
{
};

template <typename T> struct has_end<T, std::void_t<decltype(std::end(std::declval<T>()))>> : std::true_type
{
};

template <typename T> struct IsUniquePtr : std::false_type
{
};

template <typename T> struct IsUniquePtr<std::unique_ptr<T>> : std::true_type
{
};

template <typename T> struct IsSharedPtr : std::false_type
{
};

template <typename T> struct IsSharedPtr<std::shared_ptr<T>> : std::true_type
{
};

template <typename T, typename U> inline constexpr bool IsType = std::is_same_v<T, U>;

template <typename T> struct PointeeType
{
  using type = T;
};

template <typename T, typename D> struct PointeeType<std::unique_ptr<T, D>>
{
  using type = T;
};

template <typename T> struct PointeeType<std::shared_ptr<T>>
{
  using type = T;
};

template <typename T> concept IsSmartPointer = IsUniquePtr<T>::value || IsSharedPtr<T>::value;
template <typename T> concept IsRange = has_begin<T>::value && has_end<T>::value;

} // namespace mdb
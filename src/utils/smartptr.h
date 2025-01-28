/** LICENSE TEMPLATE */
#pragma once

// Base class / mixin for internal reference counting
#include "typedefs.h"
#include <atomic>
#include <memory>
#include <type_traits>

#define FORWARD_DECLARE_REF
#ifndef FORWARD_DECLARE_REFPTR
#define FORWARD_DECLARE_REFPTR
template <typename U> class RcHandle;
template <typename U> class Untraced;
#endif

#define INTERNAL_REFERENCE_COUNT(Type)                                                                            \
protected:                                                                                                        \
  /* Grant RefCountPtr access to manage reference counts */                                                       \
  template <typename U> friend class RcHandle;                                                                    \
  template <typename U> friend class Untraced;                                                                    \
  friend class RcHandle<Type>;                                                                                    \
  friend class Untraced<Type>;                                                                                    \
                                                                                                                  \
  mutable std::atomic<int> mReferenceCount{0};                                                                    \
  constexpr void IncreaseUseCount() const noexcept { mReferenceCount.fetch_add(1, std::memory_order_relaxed); }   \
                                                                                                                  \
  constexpr void DecreaseUseCount() const noexcept                                                                \
  {                                                                                                               \
    if (mReferenceCount.fetch_sub(1, std::memory_order_acq_rel) == 1) {                                           \
      delete this;                                                                                                \
    }                                                                                                             \
  }
namespace mdb {
template <typename T> class Untraced;

/// `RcHandle` is a handle to a internally reference counted type.
template <typename T> class RcHandle
{
private:
  T *mRef{nullptr};

  constexpr void
  IncrementUserCount() const noexcept
  {
    if (mRef) {
      mRef->IncreaseUseCount();
    }
  }

  constexpr void
  UserRelease() const noexcept
  {
    if (mRef) {
      mRef->DecreaseUseCount();
    }
  }

public:
  using Type = T;
  template <typename U> friend class RcHandle;
  friend class Untraced<T>;
  // Constructors
  constexpr RcHandle() = default;
  constexpr RcHandle(std::nullptr_t) noexcept : RcHandle() {};

  constexpr RcHandle(Untraced<T> &&untraced) noexcept : mRef(nullptr) { std::swap(mRef, untraced.mUnManged); }

  constexpr explicit RcHandle(T *rawPtr) noexcept : mRef(rawPtr) { IncrementUserCount(); }

  constexpr RcHandle(const RcHandle &other) noexcept : mRef(other.mRef) { IncrementUserCount(); }

  constexpr RcHandle(RcHandle &&other) noexcept : mRef(other.mRef) { other.mRef = nullptr; }

  // Implicit conversion operator from RcHandle<Derived> to RcHandle<Base>
  template <typename Derived>
  constexpr RcHandle(const RcHandle<Derived> &other) noexcept
    requires(std::is_base_of_v<T, Derived>)
      : mRef(other.mRef)
  {
    static_assert(std::is_base_of<T, Derived>::value, "Derived must be a subclass of Base");
    IncrementUserCount();
  }

  // Implicit conversion operator from RcHandle<Derived> to RcHandle<Base>
  template <typename Derived>
  constexpr RcHandle(RcHandle<Derived> &&other) noexcept
    requires(std::is_base_of_v<T, Derived>)
      : mRef(other.mRef)
  {
    other.mRef = nullptr;
  }

  // Destructor
  constexpr ~RcHandle() noexcept { UserRelease(); }

  template <typename... Args>
  constexpr static RcHandle<T>
  MakeShared(Args &&...args) noexcept
  {
    return RcHandle{new T{std::forward<Args>(args)...}};
  }

  // Assignment operators
  constexpr RcHandle &
  operator=(const RcHandle &other) noexcept
  {
    if (this != &other) {
      UserRelease();
      mRef = other.mRef;
      IncrementUserCount();
    }
    return *this;
  }

  constexpr RcHandle &
  operator=(RcHandle &&other) noexcept
  {
    if (this != &other) {
      UserRelease();
      mRef = other.mRef;
      other.mRef = nullptr;
    }
    return *this;
  }

  constexpr RcHandle &
  operator=(std::nullptr_t) noexcept
  {
    Reset();
    return *this;
  }

  // Accessors
  constexpr T *
  Get() const noexcept
  {
    return mRef;
  }

  constexpr void
  Reset() noexcept
  {
    UserRelease();
    mRef = nullptr;
  }

  constexpr Untraced<T>
  DisOwn() noexcept
  {
    T *swap = nullptr;
    std::swap(mRef, swap);
    return Untraced{swap};
  }

  constexpr T &
  operator*() const noexcept
  {
    return *mRef;
  }

  constexpr T *
  operator->() const noexcept
  {
    return mRef;
  }

  constexpr
  operator T *() const noexcept
  {
    return mRef;
  }

  constexpr explicit
  operator bool() const noexcept
  {
    return mRef != nullptr;
  }

  // Equality and inequality comparisons
  constexpr bool
  operator==(const RcHandle &other) const noexcept
  {
    return Get() == other.Get();
  }

  constexpr bool
  operator!=(const RcHandle &other) const noexcept
  {
    return Get() != other.Get();
  }

  constexpr bool
  operator==(const T *ptr) const noexcept
  {
    return Get() == ptr;
  }

  constexpr bool
  operator!=(const T *ptr) const noexcept
  {
    return Get() != ptr;
  }

  constexpr friend bool
  operator==(const T *ptr, const RcHandle &refPtr) noexcept
  {
    return ptr == refPtr.Get();
  }

  constexpr friend bool
  operator!=(const T *ptr, const RcHandle &refPtr) noexcept
  {
    return ptr != refPtr.Get();
  }
};

template <typename T> class Untraced
{
  T *mUnManged;

  friend struct RefPtrObject;
  constexpr void
  Drop() noexcept
  {
    mUnManged->DecreaseUseCount();
  }

public:
  using Type = T;
  friend class RcHandle<T>;
  constexpr Untraced(T *take) noexcept : mUnManged(take) {}
  constexpr ~Untraced() noexcept { ASSERT(mUnManged == nullptr, "Dropped ref counted object on the floor"); }
  constexpr Untraced(Untraced &&other) noexcept : mUnManged(nullptr) { std::swap(mUnManged, other.mUnManged); }

  constexpr Untraced(const Untraced &) noexcept = delete;
  constexpr Untraced(Untraced &) noexcept = delete;
  constexpr Untraced &operator=(const Untraced &) = delete;
  constexpr Untraced &operator=(Untraced &&) = delete;

  constexpr
  operator RcHandle<T>() noexcept
  {
    return RcHandle{std::move(*this)};
  }

  constexpr RcHandle<T>
  Take() noexcept
  {
    return RcHandle<T>{std::move(*this)};
  }
};

template <typename T> using Ref = RcHandle<T>;

template <typename T> struct IsRefPointerCheck : std::false_type
{
};

// Partial specialization: matches when T is of type RefPtr<U>.
template <template <typename> class Template, typename U>
struct IsRefPointerCheck<Template<U>>
    : std::conditional_t<std::is_same_v<Template<U>, Ref<U>>, std::true_type, std::false_type>
{
};

template <typename T> struct IsUniquePtrCheck : std::false_type
{
};

template <template <typename> class Template, typename U>
struct IsUniquePtrCheck<Template<U>>
    : std::conditional_t<std::is_same_v<Template<U>, std::unique_ptr<U>>, std::true_type, std::false_type>
{
};

template <typename TypeToCheck> concept IsRefPointer = IsRefPointerCheck<TypeToCheck>::value;
template <typename TypeToCheck> concept IsUniquePtr = IsUniquePtrCheck<TypeToCheck>::value;
} // namespace mdb
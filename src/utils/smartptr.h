/** LICENSE TEMPLATE */
#pragma once

// Base class / mixin for internal reference counting
#include "typedefs.h"
#include <atomic>
#include <common.h>
#include <memory>
#include <type_traits>

#define FORWARD_DECLARE_REF
#ifndef FORWARD_DECLARE_REFPTR
#define FORWARD_DECLARE_REFPTR
namespace mdb {
template <typename U> class RcHandle;
template <typename U> class Untraced;
} // namespace mdb
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

#define REF_COUNTED_WITH_WEAKREF_SUPPORT(Type)                                                                    \
protected:                                                                                                        \
  template <typename U> friend class RcHandle;                                                                    \
  template <typename U> friend class Untraced;                                                                    \
  friend class RcHandle<Type>;                                                                                    \
  friend class Untraced<Type>;                                                                                    \
  mdb::ControlBlock<Type> *mControlBlock;                                                                         \
                                                                                                                  \
public:                                                                                                           \
  constexpr void IncreaseUseCount() const noexcept { mControlBlock->IncreaseStrongReference(); }                  \
                                                                                                                  \
  constexpr void DecreaseUseCount() const noexcept                                                                \
  {                                                                                                               \
    mControlBlock->DecreaseStrongReference(const_cast<Type *>(static_cast<const Type *>(this)));                  \
  }

namespace mdb {
template <typename T> class Untraced;

template <typename T> struct ControlBlock
{
  std::atomic<int> mReferenceCount;
  std::atomic<int> mWeakReference;

  void
  IncreaseStrongReference() noexcept
  {
    mReferenceCount.fetch_add(1, std::memory_order_relaxed);
  }

  void
  IncreaseWeakReference() noexcept
  {
    mWeakReference.fetch_add(1, std::memory_order_relaxed);
  }

  void
  DecreaseStrongReference(T *This) noexcept
  {
    if (mReferenceCount.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      delete This;
      if (mWeakReference == 0) {
        delete this;
      }
    }
  }

  void
  DecreaseWeakReference() noexcept
  {
    if (mWeakReference.fetch_sub(1, std::memory_order_acq_rel) == 1) {
      delete this;
    }
  }
};

template <typename T> class WeakRef
{
  T *mPtr;
  ControlBlock<T> *mControlBlock;
  friend class RcHandle<T>;

  // Should be constructed by RcHandle<T>::WeakRef()
  WeakRef(T *ptr, ControlBlock<T> *controlBlock) noexcept : mPtr(ptr), mControlBlock(controlBlock) {}

public:
  WeakRef() noexcept : mPtr(nullptr), mControlBlock(nullptr) {}
  ~WeakRef() noexcept { mControlBlock->DecreaseWeakReference(); }

  bool
  IsAlive() noexcept
  {
    return mControlBlock->mReferenceCount > 0;
  }

  RcHandle<T>
  Acquire() const noexcept
  {
    if (!IsAlive()) {
      return nullptr;
    }

    return RcHandle{mPtr};
  }
};

template <typename T> concept HasControlBlock = requires(T t) { t.mControlBlock; };

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

  WeakRef<T>
  Weak() noexcept
    requires HasControlBlock<T>
  {
    if (!mRef) [[unlikely]] {
      return nullptr;
    }
    mRef->mControlBlock->IncreaseWeakReference();

    return WeakRef<T>{mRef, mRef->mControlBlock};
  }

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

  // Ref<T> constructor for types that support weak references.
  template <typename... Args>
  constexpr static RcHandle<T>
  MakeShared(Args &&...args) noexcept
    requires HasControlBlock<T>
  {
    auto t = T::CreateForRef(std::forward<Args>(args)...);
    t->mControlBlock = new ControlBlock<T>{};
    return RcHandle{t};
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
  DisOwn() && noexcept
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

template <typename T>
concept IsRefCountable = requires(T *t) {
  { RcHandle<T>{t} };
};
namespace js {
template <typename Derived, IsRefCountable WrappedType, StringLiteral string> struct RefPtrJsObject;
}

template <typename T> class Untraced
{
  T *mUnManged;

  /// Drop and Forget are purposefully private metods. And the class `RefPtrJsObject` and `RcHandle` are, for
  /// that same reason, friend classes. RefPtrJsObject uses the forget & drop mechanism when participating in GC
  /// and automatic life time memory management by the js embedding. This is also the reason why
  /// Increase/DecreaseCount are private methods because they are not supposed to be used by any other interfaces
  /// than the ones explicitly allowed to, via friend declarations.
  constexpr void
  Drop() noexcept
  {
    mUnManged->DecreaseUseCount();
    T *result{nullptr};
    std::swap(result, mUnManged);
  }

  constexpr T *
  Forget() noexcept
  {
    T *result{nullptr};
    std::swap(result, mUnManged);
    return result;
  }

  // Also only callable from RefPtrJsObject, that manually manages reference counting.
  constexpr RcHandle<T>
  CloneReference() noexcept
  {
    return RcHandle<T>{Forget()};
  }

  using Type = T;
  template <typename Derived, IsRefCountable WrappedType, StringLiteral string> friend struct js::RefPtrJsObject;
  friend class RcHandle<T>;

  constexpr Untraced(T *take) noexcept : mUnManged(take) {}

public:
  // It's fine to move Untraced and it's ok to destroy Untraced in non-friend contexts (because in those
  // contexts, you transform the untraced to a ref counted pointer via .Take() or direct conversion)
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
/** LICENSE TEMPLATE */
#pragma once

// Base class / mixin for internal reference counting
#include <atomic>
#include <common.h>
#include <common/typedefs.h>
#include <memory>
#include <type_traits>

#define FORWARD_DECLARE_REF
#ifndef FORWARD_DECLARE_REFPTR
#define FORWARD_DECLARE_REFPTR
namespace mdb {
template <typename T> class RefCountControl
{
public:
  static void
  IncRefCount(const T &t) noexcept
  {
    t.IncreaseUseCount();
  }

  static void
  DecRefCount(const T &t) noexcept
  {
    t.DecreaseUseCount();
  }
};

template <typename T>
concept RefCountable = requires(T *t) {
  RefCountControl<T>::IncRefCount(*t);
  RefCountControl<T>::DecRefCount(*t);
};

template <typename U> class RefPtr;
template <typename U> class LeakedRef;
} // namespace mdb
#endif

#define INTERNAL_REFERENCE_COUNT(Type)                                                                            \
protected:                                                                                                        \
  /* Grant RefCountPtr access to manage reference counts */                                                       \
  template <typename U> friend class RefPtr;                                                                      \
  template <typename U> friend class LeakedRef;                                                                   \
  friend class RefPtr<Type>;                                                                                      \
  friend class LeakedRef<Type>;                                                                                   \
                                                                                                                  \
  mutable std::atomic<int> mReferenceCount{ 0 };                                                                  \
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
  template <typename U> friend class RefPtr;                                                                      \
  template <typename U> friend class LeakedRef;                                                                   \
  friend class RefPtr<Type>;                                                                                      \
  friend class LeakedRef<Type>;                                                                                   \
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

template <typename T> class LeakedRef;

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
  friend class RefPtr<T>;

  // Should be constructed by RefPtr<T>::WeakRef()
  WeakRef(T *ptr, ControlBlock<T> *controlBlock) noexcept : mPtr(ptr), mControlBlock(controlBlock) {}

public:
  WeakRef() noexcept : mPtr(nullptr), mControlBlock(nullptr) {}
  ~WeakRef() noexcept { mControlBlock->DecreaseWeakReference(); }

  bool
  IsAlive() noexcept
  {
    return mControlBlock->mReferenceCount > 0;
  }

  RefPtr<T>
  Acquire() const noexcept
  {
    if (!IsAlive()) {
      return nullptr;
    }

    return RefPtr{ mPtr };
  }

  constexpr
  operator bool() const noexcept
  {
    return mPtr != nullptr;
  }
};

template <typename T> concept HasControlBlock = requires(T t) { t.mControlBlock; };

// Access to RefPtr internals.
// Add friends that is allowed access directly into the type.
struct RefPtrLeakAccessKey
{
private:
  // Only this helper can create keys
  friend struct JSBindingLeakHelper;
  constexpr RefPtrLeakAccessKey() noexcept = default;
};

/// `RefPtr` is a handle to a internally reference counted type.
template <typename T> class RefPtr
{
private:
  T *mRef{ nullptr };

  constexpr void
  IncrementUserCount() const noexcept
  {
    if (mRef) {
      mRef->IncreaseUseCount();
    }
  }

  constexpr void
  DecrementUserCount() const noexcept
  {
    if (mRef) {
      mRef->DecreaseUseCount();
    }
  }

public:
  using Type = T;
  template <typename U> friend class RefPtr;
  friend class LeakedRef<T>;
  // Constructors
  constexpr RefPtr() = default;
  constexpr RefPtr(std::nullptr_t) noexcept : RefPtr() {};

  constexpr RefPtr(LeakedRef<T> &&leakedref) noexcept : mRef(nullptr) { std::swap(mRef, leakedref.mUnManged); }

  constexpr explicit RefPtr(T *rawPtr) noexcept : mRef(rawPtr) { IncrementUserCount(); }

  constexpr RefPtr(const RefPtr &other) noexcept : mRef(other.mRef) { IncrementUserCount(); }

  constexpr RefPtr(RefPtr &&other) noexcept : mRef(other.mRef) { other.mRef = nullptr; }

  WeakRef<T>
  Weak() noexcept
    requires HasControlBlock<T>
  {
    if (!mRef) [[unlikely]] {
      return nullptr;
    }
    mRef->mControlBlock->IncreaseWeakReference();

    return WeakRef<T>{ mRef, mRef->mControlBlock };
  }

  constexpr LeakedRef<T>
  Leak(RefPtrLeakAccessKey) noexcept
  {
    T *swap = nullptr;
    std::swap(mRef, swap);
    return LeakedRef<T>{ swap };
  }

  // Implicit conversion operator from RefPtr<Derived> to RefPtr<Base>
  template <typename Derived>
  constexpr RefPtr(const RefPtr<Derived> &other) noexcept
    requires(std::is_base_of_v<T, Derived>)
      : mRef(other.mRef)
  {
    static_assert(std::is_base_of<T, Derived>::value, "Derived must be a subclass of Base");
    IncrementUserCount();
  }

  // Implicit conversion operator from RefPtr<Derived> to RefPtr<Base>
  template <typename Derived>
  constexpr RefPtr(RefPtr<Derived> &&other) noexcept
    requires(std::is_base_of_v<T, Derived>)
      : mRef(other.mRef)
  {
    other.mRef = nullptr;
  }

  // Destructor
  constexpr ~RefPtr() noexcept { DecrementUserCount(); }

  template <typename... Args>
  constexpr static RefPtr<T>
  MakeShared(Args &&...args) noexcept
  {
    return RefPtr{ new T{ std::forward<Args>(args)... } };
  }

  // Ref<T> constructor for types that support weak references.
  template <typename... Args>
  constexpr static RefPtr<T>
  MakeShared(Args &&...args) noexcept
    requires HasControlBlock<T>
  {
    auto t = T::CreateForRef(std::forward<Args>(args)...);
    t->mControlBlock = new ControlBlock<T>{};
    return RefPtr{ t };
  }

  // Assignment operators
  constexpr RefPtr &
  operator=(const RefPtr &other) noexcept
  {
    if (this != &other) {
      DecrementUserCount();
      mRef = other.mRef;
      IncrementUserCount();
    }
    return *this;
  }

  constexpr RefPtr &
  operator=(RefPtr &&other) noexcept
  {
    if (this != &other) {
      DecrementUserCount();
      mRef = other.mRef;
      other.mRef = nullptr;
    }
    return *this;
  }

  constexpr RefPtr &
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
    DecrementUserCount();
    mRef = nullptr;
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
  operator==(const RefPtr &other) const noexcept
  {
    return Get() == other.Get();
  }

  constexpr bool
  operator!=(const RefPtr &other) const noexcept
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
  operator==(const T *ptr, const RefPtr &refPtr) noexcept
  {
    return ptr == refPtr.Get();
  }

  constexpr friend bool
  operator!=(const T *ptr, const RefPtr &refPtr) noexcept
  {
    return ptr != refPtr.Get();
  }
};

template <typename T>
concept IsRefCountable = requires(T *t) {
  { RefPtr<T>{ t } };
};

template <typename T> class LeakedRef
{
  T *mUnManged;

  friend class RefPtr<T>;

  constexpr LeakedRef(T *take) noexcept : mUnManged(take) {}

public:
  /// Drop and Forget are purposefully private metods. And the class `RefPtrJsObject` and `RefPtr` are, for
  /// that same reason, friend classes. RefPtrJsObject uses the forget & drop mechanism when participating in GC
  /// and automatic life time memory management by the js embedding. This is also the reason why
  /// Increase/DecreaseCount are private methods because they are not supposed to be used by any other interfaces
  /// than the ones explicitly allowed to, via friend declarations.
  constexpr void
  Drop() noexcept
  {
    mUnManged->DecreaseUseCount();
    T *result{ nullptr };
    std::swap(result, mUnManged);
  }

  constexpr T *
  Forget() noexcept
  {
    T *result{ nullptr };
    std::swap(result, mUnManged);
    return result;
  }

  // Also only callable from RefPtrJsObject, that manually manages reference counting.
  constexpr RefPtr<T>
  CloneReference() noexcept
  {
    return RefPtr<T>{ Forget() };
  }

  // It's fine to move LeakedRef and it's ok to destroy LeakedRef in non-friend contexts (because in those
  // contexts, you transform the leakedref to a ref counted pointer via .Take() or direct conversion)
  constexpr ~LeakedRef() noexcept { ASSERT(mUnManged == nullptr, "Dropped ref counted object on the floor"); }
  constexpr LeakedRef(LeakedRef &&other) noexcept : mUnManged(nullptr) { std::swap(mUnManged, other.mUnManged); }

  constexpr LeakedRef(const LeakedRef &) noexcept = delete;
  constexpr LeakedRef(LeakedRef &) noexcept = delete;
  constexpr LeakedRef &operator=(const LeakedRef &) = delete;
  constexpr LeakedRef &operator=(LeakedRef &&) = delete;

  constexpr
  operator RefPtr<T>() noexcept
  {
    return RefPtr{ std::move(*this) };
  }

  constexpr RefPtr<T>
  Take() noexcept
  {
    return RefPtr<T>{ std::move(*this) };
  }
};

template <typename T> using Ref = RefPtr<T>;

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
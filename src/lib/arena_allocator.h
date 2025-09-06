/** LICENSE TEMPLATE */
#pragma once
// mdb
#include <common/macros.h>
#include <common/typedefs.h>
#include <utils/util.h>

// stdlib
#include <memory>
#include <memory_resource>

// system
#include <sys/user.h>

namespace mdb::alloc {
class ArenaResource;

struct Page
{
  u32 count;

  constexpr u64
  SizeBytes() const noexcept
  {
    return SystemPagesInBytes(count);
  }
};

// TODO(simon): write as it's own class?
using ArenaAllocatorPool = std::vector<ArenaResource *>;

// Class that takes a reference to a `ArenaAllocator` and upon exit of scope (destructor gets run) it resets the
// arena.

// A temporary bump-allocator.
class ArenaResource : public std::pmr::memory_resource
{

  u8 *mAllocatedBuffer;
  std::size_t mAllocated;
  std::size_t mArenaCapacity;

  ArenaResource(std::size_t allocBlockSize) noexcept;

  bool ExtendAllocation(Page pageCount) noexcept;

public:
  class ScopedArenaAllocator
  {
    ArenaResource *mAllocator;
    u64 mStartOffset{ 0 };

    ArenaAllocatorPool *mContainingPool{ nullptr };

  public:
    MOVE_ONLY(ScopedArenaAllocator);

    explicit ScopedArenaAllocator(ArenaResource *allocator) noexcept;
    explicit ScopedArenaAllocator(ArenaResource *allocator, ArenaAllocatorPool *containingPool) noexcept;
    ~ScopedArenaAllocator() noexcept;
    ScopedArenaAllocator(ScopedArenaAllocator &&move) noexcept;

    // I'm not sure a = std::move(b) makes sense for this type.
    ScopedArenaAllocator &operator=(ScopedArenaAllocator &&move) noexcept = delete;

    ArenaResource *GetAllocator() const noexcept;
    operator ArenaResource *() const noexcept { return GetAllocator(); }

    template <typename T, typename... Args>
    T *
    Allocate(Args &&...args) noexcept
    {
      return mAllocator->Allocate<T>(std::forward<Args>(args)...);
    }
  };

  using UniquePtr = std::unique_ptr<ArenaResource>;
  using SharedPtr = std::shared_ptr<ArenaResource>;
  ~ArenaResource() noexcept override;

  static ArenaResource *Create(Page pagesToAllocate) noexcept;
  // Creates an arena allocator. `upstreamResource` can be null, if you don't want the arena allocator
  // to be able to allocate more memory than it's pre-allocated block.
  static UniquePtr CreateUniquePtr(Page pagesToAllocate) noexcept;
  static SharedPtr CreateShared(Page pagesToAllocate) noexcept;

  template <typename T, typename... Args>
  T *
  Allocate(Args &&...args) noexcept
  {
    std::pmr::polymorphic_allocator<T> pmrAlloc{ this };
    auto ptr = pmrAlloc.template allocate_object<T>(1);
    if constexpr (requires { std::construct_at(ptr, std::forward<Args>(args)..., this); }) {
      // For types that are allocator aware, pass "this" allocator into them
      return std::construct_at(ptr, std::forward<Args>(args)..., this);
    } else {
      return std::construct_at(ptr, std::forward<Args>(args)...);
    }
  }

  u64 CurrentlyAllocated() const noexcept;
  void Reset() noexcept;
  void Reset(u64 previousOffset) noexcept;
  // Using RAII we can get the arena allocator to reset upon function exit
  ScopedArenaAllocator ScopeAllocation() noexcept;

  // Interface Implementation.
  void *do_allocate(std::size_t bytes, std::size_t alignment) override;
  void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override;
  bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override;
};

using ScopedArenaAllocator = ArenaResource::ScopedArenaAllocator;

template <std::size_t N> class StackBufferResource : public std::pmr::memory_resource
{
public:
  void
  release() noexcept
  {
    mMemoryOffset = 0;
  }

  constexpr std::size_t
  GetCapacity() noexcept
  {
    return N;
  }

protected:
  void *
  do_allocate(std::size_t bytes, std::size_t alignment) override
  {
    VERIFY(alignment != 0 && (alignment & (alignment - 1)) == 0, "Bad alignment by stack allocator.");

    std::uintptr_t base = reinterpret_cast<std::uintptr_t>(mByteStorage) + mMemoryOffset;
    std::size_t space = N - mMemoryOffset;

    std::uintptr_t aligned = (base + (alignment - 1)) & ~(alignment - 1);
    std::size_t adjustment = aligned - base;

    VERIFY(adjustment + bytes < space,
      "Stack allocator memory exhausted! Requested {} bytes, available: {}",
      bytes,
      space);

    mMemoryOffset += adjustment + bytes;
    return reinterpret_cast<void *>(aligned);
  }

  void
  do_deallocate(void *, std::size_t, std::size_t) noexcept override
  {
    // no-op
  }

  bool
  do_is_equal(const std::pmr::memory_resource &other) const noexcept override
  {
    return this == &other;
  }

private:
  alignas(std::max_align_t) std::byte mByteStorage[N];
  std::size_t mMemoryOffset{ 0 };
};

template <size_t StackSize> class StackAllocator
{
  std::array<u8, StackSize> mMemory;
  std::pmr::monotonic_buffer_resource mMemoryResource{ mMemory.data(), mMemory.size() * sizeof(unsigned) };
  std::pmr::polymorphic_allocator<> mUsingStackAllocator{ &mMemoryResource };

public:
  std::pmr::monotonic_buffer_resource &Resource() noexcept;
  std::pmr::polymorphic_allocator<> &Allocator() noexcept;
};
} // namespace mdb::alloc
#pragma once
#include "typedefs.h"
#include "utils/macros.h"
#include "utils/scope_defer.h"
#include <memory>
#include <memory_resource>
#include <sys/user.h>

class ArenaAllocator;

// Class that takes a reference to a `ArenaAllocator` and upon exit of scope (destructor gets run) it resets the
// arena.
class ScopedArenaAllocator
{
  ArenaAllocator *mAllocator;

public:
  MOVE_ONLY(ScopedArenaAllocator);
  explicit ScopedArenaAllocator(ArenaAllocator *allocator) noexcept;
  ~ScopedArenaAllocator() noexcept;
  ScopedArenaAllocator(ScopedArenaAllocator&& move) noexcept;

  // I'm not sure a = std::move(b) makes sense for this type.
  ScopedArenaAllocator& operator=(ScopedArenaAllocator&& move) noexcept = delete;

  ArenaAllocator *GetAllocator() const noexcept;
  operator ArenaAllocator *() const noexcept { return GetAllocator(); }
};

class ArenaAllocator : public std::pmr::memory_resource
{
  std::pmr::memory_resource *mResource;

  u8 *mAllocatedBuffer;
  std::size_t mAllocated;
  std::size_t mArenaCapacity;

  ArenaAllocator(std::size_t allocBlockSize, std::pmr::memory_resource *upstreamResource) noexcept;

public:
  using UniquePtr = std::unique_ptr<ArenaAllocator>;
  using SharedPtr = std::shared_ptr<ArenaAllocator>;
  ~ArenaAllocator() noexcept override;

  // Creates an arena allocator. `upstreamResource` can be null, if you don't want the arena allocator
  // to be able to allocate more memory than it's pre-allocated block.
  static UniquePtr Create(size_t allocSize, std::pmr::memory_resource *upstreamResource) noexcept;
  static SharedPtr CreateShared(size_t allocSize, std::pmr::memory_resource *upstreamResource) noexcept;
  void Reset() noexcept;
  // Using RAII we can get the arena allocator to reset upon function exit
  ScopedArenaAllocator ScopeAllocation() noexcept;

  // Interface Implementation.
  void *do_allocate(std::size_t bytes, std::size_t alignment) override;
  void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override;
  bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override;
};

template <size_t StackSize> class StackAllocator
{
  std::array<u8, StackSize> mMemory;
  std::pmr::monotonic_buffer_resource mMemoryResource{mMemory.data(), mMemory.size() * sizeof(unsigned)};
  std::pmr::polymorphic_allocator<> mUsingStackAllocator{&mMemoryResource};

public:
  std::pmr::monotonic_buffer_resource &Resource() noexcept;
  std::pmr::polymorphic_allocator<> &Allocator() noexcept;
};
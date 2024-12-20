#pragma once
#include "typedefs.h"
#include <memory>
#include <memory_resource>
#include <sys/user.h>

class ArenaAllocator : public std::pmr::memory_resource
{
  std::pmr::memory_resource *mResource;

  u8* mAllocatedBuffer;
  std::size_t mAllocated;
  std::size_t mArenaCapacity;

  ArenaAllocator(std::size_t allocBlockSize, std::pmr::memory_resource *upstreamResource) noexcept;
public:
  using UniquePtr = std::unique_ptr<ArenaAllocator>;
  using SharedPtr = std::shared_ptr<ArenaAllocator>;
  ~ArenaAllocator() noexcept override;

  // Creates an arena allocator. `upstreamResource` can be null, if you don't want the arena allocator
  // to be able to allocate more memory than it's pre-allocated block.
  static UniquePtr Create(size_t allocSize, std::pmr::memory_resource* upstreamResource) noexcept;
  static SharedPtr CreateShared(size_t allocSize, std::pmr::memory_resource* upstreamResource) noexcept;

  void *do_allocate(std::size_t bytes, std::size_t alignment) override;
  void do_deallocate(void *p, std::size_t bytes, std::size_t alignment) override;
  bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override;

  void reset() noexcept;
};

template <size_t StackSize>
class StackAllocator {
  std::array<u8, StackSize> mMemory;
  std::pmr::monotonic_buffer_resource mMemoryResource{mMemory.data(), mMemory.size() * sizeof(unsigned)};
  std::pmr::polymorphic_allocator<> mUsingStackAllocator{&mMemoryResource};

public:
  std::pmr::monotonic_buffer_resource& Resource() noexcept;
  std::pmr::polymorphic_allocator<>& Allocator() noexcept;
};
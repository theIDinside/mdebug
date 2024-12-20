#include "arena_allocator.h"
#include "common.h"
#include "tracee/util.h"
#include <cstdlib>
#include <memory_resource>

ArenaAllocator::ArenaAllocator(std::size_t allocBlockSize, std::pmr::memory_resource *upstreamResource) noexcept
    : mResource(upstreamResource), mAllocated(0), mArenaCapacity(allocBlockSize)
{
  int allocResult = posix_memalign((void **)&mAllocatedBuffer, SystemVectorExtensionSize(), allocBlockSize);
  MUST_HOLD(allocResult == 0, "posix_memalign failed");
}

ArenaAllocator::~ArenaAllocator() noexcept { free(mAllocatedBuffer); }

/*static*/
ArenaAllocator::UniquePtr
ArenaAllocator::Create(size_t allocSize, std::pmr::memory_resource *upstreamResource) noexcept
{
  return std::unique_ptr<ArenaAllocator>(new ArenaAllocator{allocSize, upstreamResource});
}

/*static*/
ArenaAllocator::SharedPtr
ArenaAllocator::CreateShared(size_t allocSize, std::pmr::memory_resource *upstreamResource) noexcept
{
  return std::shared_ptr<ArenaAllocator>(new ArenaAllocator{allocSize, upstreamResource});
}

void *
ArenaAllocator::do_allocate(std::size_t bytes, std::size_t alignment)
{
  // (0b101 + 0b100 - 0b1) & ~(0b100 - 0b1 => 0b11)
  //
  const std::size_t possiblyAdjustedOffset = (mAllocated + alignment - 1) & ~(alignment - 1);
  MUST_HOLD((possiblyAdjustedOffset + bytes) < mArenaCapacity,
            "Dynamic arena allocator not yet implemented. For now we crash.");
  void *p = mAllocatedBuffer + possiblyAdjustedOffset;
  mAllocated = possiblyAdjustedOffset + bytes;
  return p;
}

void
ArenaAllocator::do_deallocate(void *p, std::size_t bytes, std::size_t alignment)
{
  MUST_HOLD(p < (mAllocatedBuffer + mArenaCapacity),
            "The arena allocator doesn't support dynamic allocations when memory runs out, yet");
}

bool
ArenaAllocator::do_is_equal(const std::pmr::memory_resource &other) const noexcept
{
  return this == &other;
}

template <size_t N>
std::pmr::monotonic_buffer_resource &
StackAllocator<N>::Resource() noexcept
{
  return mMemoryResource;
}

template <size_t N>
std::pmr::polymorphic_allocator<> &
StackAllocator<N>::Allocator() noexcept
{
  return mUsingStackAllocator;
}
/** LICENSE TEMPLATE */
#include "arena_allocator.h"
#include "common.h"
#include <cstdlib>
#include <memory_resource>
#include <sys/mman.h>
namespace mdb::alloc {
ScopedArenaAllocator::ScopedArenaAllocator(ArenaAllocator *allocator) noexcept : mAllocator(allocator)
{
  mStartOffset = mAllocator->CurrentlyAllocated();
}

ScopedArenaAllocator::~ScopedArenaAllocator() noexcept
{
  if (mAllocator) {
    mAllocator->Reset(mStartOffset);
  }
}

ScopedArenaAllocator::ScopedArenaAllocator(ScopedArenaAllocator &&move) noexcept : mAllocator(nullptr)
{
  std::swap(mAllocator, move.mAllocator);
}

ArenaAllocator *
ScopedArenaAllocator::GetAllocator() const noexcept
{
  return mAllocator;
}

ArenaAllocator::ArenaAllocator(std::size_t allocBlockSize, std::pmr::memory_resource *upstreamResource) noexcept
    : mResource(upstreamResource), mAllocated(0), mArenaCapacity(allocBlockSize)
{
  auto result = mmap(nullptr, allocBlockSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  MUST_HOLD(result != MAP_FAILED, "posix_memalign failed");
  mAllocatedBuffer = (u8 *)result;
}

ArenaAllocator::~ArenaAllocator() noexcept { munmap(mAllocatedBuffer, mArenaCapacity); }

bool
ArenaAllocator::ExtendAllocation(Page pageCount) noexcept
{
  auto address = mAllocatedBuffer + mArenaCapacity;
  auto result = mmap(address, pageCount.SizeBytes(), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (result == MAP_FAILED) {
    return false;
  }

  // we don't have to do anything more, we've succeeded, and we no the mapping is consecutive because we manage it.
  mArenaCapacity += pageCount.SizeBytes();
  return true;
}

/*static*/
ArenaAllocator::UniquePtr
ArenaAllocator::Create(Page pagesToAllocate, std::pmr::memory_resource *upstreamResource) noexcept
{
  return std::unique_ptr<ArenaAllocator>(new ArenaAllocator{pagesToAllocate.SizeBytes(), upstreamResource});
}

/*static*/
ArenaAllocator::SharedPtr
ArenaAllocator::CreateShared(Page pagesToAllocate, std::pmr::memory_resource *upstreamResource) noexcept
{
  return std::shared_ptr<ArenaAllocator>(new ArenaAllocator{pagesToAllocate.SizeBytes(), upstreamResource});
}

u64
ArenaAllocator::CurrentlyAllocated() const noexcept
{
  return mAllocated;
}

void
ArenaAllocator::Reset() noexcept
{
  mAllocated = 0;
}

void
ArenaAllocator::Reset(u64 previousOffset) noexcept
{
  ASSERT(previousOffset <= mAllocated, "Previous offset is not less than or equal to current alloc offset");
  mAllocated = previousOffset;
}

ScopedArenaAllocator
ArenaAllocator::ScopeAllocation() noexcept
{
  return ScopedArenaAllocator{this};
}

void *
ArenaAllocator::do_allocate(std::size_t bytes, std::size_t alignment)
{
  const std::size_t possiblyAdjustedOffset = (mAllocated + alignment - 1) & ~(alignment - 1);
  MUST_HOLD(possiblyAdjustedOffset + bytes < mArenaCapacity,
            "Extending Arena Allocator size not yet implemented/supported fully. ArenaAllocator::ExtendAllocation "
            "is what needs additional work.");
  void *p = mAllocatedBuffer + possiblyAdjustedOffset;
  mAllocated = possiblyAdjustedOffset + bytes;
  return p;
}

void
ArenaAllocator::do_deallocate(void *p, std::size_t, std::size_t)
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
} // namespace mdb::alloc
/** LICENSE TEMPLATE */
#include "arena_allocator.h"
#include "common.h"
#include "events/event.h"
#include <cstdlib>
#include <memory_resource>
#include <sys/mman.h>
namespace mdb::alloc {
ArenaResource::ScopedArenaAllocator::ScopedArenaAllocator(ArenaResource *allocator) noexcept
    : mAllocator(allocator)
{
  mStartOffset = mAllocator->CurrentlyAllocated();
}

ArenaResource::ScopedArenaAllocator::ScopedArenaAllocator(
  ArenaResource *allocator, ArenaAllocatorPool *containingPool) noexcept
    : mAllocator(allocator), mContainingPool(containingPool)
{
}

ArenaResource::ScopedArenaAllocator::~ScopedArenaAllocator() noexcept
{
  if (mAllocator) {
    mAllocator->Reset(mStartOffset);
    const auto CompareAllocator = [alloc = mAllocator](auto *allocator) { return allocator == alloc; };
    if (mContainingPool && none_of(*mContainingPool, std::move(CompareAllocator))) {
      mContainingPool->push_back(mAllocator);
    }
  }
}

ArenaResource::ScopedArenaAllocator::ScopedArenaAllocator(ScopedArenaAllocator &&move) noexcept
    : mAllocator(nullptr)
{
  std::swap(mAllocator, move.mAllocator);
}

ArenaResource *
ArenaResource::ScopedArenaAllocator::GetAllocator() const noexcept
{
  return mAllocator;
}

ArenaResource::ArenaResource(std::size_t allocBlockSize) noexcept : mAllocated(0), mArenaCapacity(allocBlockSize)
{
  auto result = mmap(nullptr, allocBlockSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  MUST_HOLD(result != MAP_FAILED, "posix_memalign failed");
  mAllocatedBuffer = (u8 *)result;
}

ArenaResource::~ArenaResource() noexcept { munmap(mAllocatedBuffer, mArenaCapacity); }

bool
ArenaResource::ExtendAllocation(Page pageCount) noexcept
{
  auto address = mAllocatedBuffer + mArenaCapacity;
  auto result = mmap(address,
    pageCount.SizeBytes(),
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
    -1,
    0);
  if (result == MAP_FAILED) {
    return false;
  }

  // we don't have to do anything more, we've succeeded, and we no the mapping is consecutive because we manage it.
  mArenaCapacity += pageCount.SizeBytes();
  return true;
}

/* static */ ArenaResource *
ArenaResource::Create(Page pagesToAllocate) noexcept
{
  return new ArenaResource{ pagesToAllocate.SizeBytes() };
}

/*static*/
ArenaResource::UniquePtr
ArenaResource::CreateUniquePtr(Page pagesToAllocate) noexcept
{
  return std::unique_ptr<ArenaResource>(Create(pagesToAllocate));
}

/*static*/
ArenaResource::SharedPtr
ArenaResource::CreateShared(Page pagesToAllocate) noexcept
{
  return std::shared_ptr<ArenaResource>(Create(pagesToAllocate));
}

u64
ArenaResource::CurrentlyAllocated() const noexcept
{
  return mAllocated;
}

void
ArenaResource::Reset() noexcept
{
  mAllocated = 0;
}

void
ArenaResource::Reset(u64 previousOffset) noexcept
{
  ASSERT(previousOffset <= mAllocated, "Previous offset is not less than or equal to current alloc offset");
  mAllocated = previousOffset;
}

ScopedArenaAllocator
ArenaResource::ScopeAllocation() noexcept
{
  return ScopedArenaAllocator{ this };
}

void *
ArenaResource::do_allocate(std::size_t bytes, std::size_t alignment)
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
ArenaResource::do_deallocate(void *p, std::size_t, std::size_t)
{
  MUST_HOLD(p < (mAllocatedBuffer + mArenaCapacity),
    "The arena allocator doesn't support dynamic allocations when memory runs out, yet");
}

bool
ArenaResource::do_is_equal(const std::pmr::memory_resource &other) const noexcept
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
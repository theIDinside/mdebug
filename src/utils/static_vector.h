/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "typedefs.h"
#include <cmath>
#include <cstring>
#include <immintrin.h>

namespace utils {

// Minimum allocation of MDB_PAGE_SIZE
// Meant to hold "trivial" types.
template <typename T> class StaticVector
{
public:
  using OwnPtr = std::unique_ptr<StaticVector<T>>;
  StaticVector(u64 capacity) noexcept : size(0), cap(capacity), cap_bytes(capacity * sizeof(T))
  {
    const auto bytes_required = sizeof(T) * capacity;
    if (bytes_required < MDB_PAGE_SIZE) {
      data = mmap_buffer<T>(MDB_PAGE_SIZE);
      cap_bytes = MDB_PAGE_SIZE;
    } else {
      const auto pages_required =
        std::ceil(static_cast<double>(bytes_required) / static_cast<double>(MDB_PAGE_SIZE));
      cap_bytes = MDB_PAGE_SIZE * static_cast<u64>(pages_required);
      data = mmap_buffer<T>(cap_bytes);
    }
  }

  ~StaticVector() noexcept { munmap(data, cap_bytes); }

  void
  set_size(u64 size) noexcept
  {
    this->size = size;
  }

  void
  push(T &&t) noexcept
  {
    *(data + size) = t;
  }

  template <typename U = T>
  U *
  data_ptr() noexcept
  {
    return (U *)data;
  }

  std::span<T>
  span() noexcept
  {
    return std::span<T>{data, size};
  }

private:
  T *data;
  u64 size;
  u64 cap;
  u64 cap_bytes;
};

template <typename T, u64 OnStackTCount> class StackArray
{
public:
  StackArray() noexcept {}
  ~StackArray() = default;

  constexpr auto
  Capacity() const noexcept -> u64
  {
    return OnStackTCount;
  }
  constexpr auto
  Size() const noexcept -> u64
  {
    return mSize;
  }

  template <typename... Args>
  constexpr auto
  ConstructAdd(Args &&...args) -> u64
  {
    ASSERT(Size() < Capacity(), "No more room in StackArray");
    static_assert(std::is_constructible_v<T, Args...>, "T is not constructible from args!");
    auto ptr = new (mArray + Size()) T{std::forward<Args>(args)...};
    if (ptr != nullptr) {
      ++mSize;
    }
    return Size();
  }

  constexpr auto
  Add(const T &t)
  {
    ASSERT(Size() < Capacity(), "No more room in StackArray");
    mArray[Size()] = t;
    ++mSize;
    return Size();
  }

  constexpr auto
  Add(T &&t) noexcept
  {
    static_assert(std::is_move_assignable_v<T> || std::is_move_constructible_v<T>,
                  "T has no move constructor opportunities");
    ASSERT(Size() < Capacity(), "No more room in StackArray");
    if constexpr (!std::is_move_assignable_v<T>) {
      new (mArray + Size()) T{std::move(t)};
    } else {
      mArray[Size()] = std::move(t);
    }
    ++mSize;
    return Size();
  }

  constexpr auto
  begin() const -> T *
  {
    return mArray;
  }

  constexpr auto
  end() const -> T *
  {
    return mArray + Size();
  }

private:
  u32 mSize{0};
  alignas(T) T mArray[OnStackTCount];
};

template <u32 Cap> class StackString
{
public:
  using value_type = char;
  constexpr auto
  Capacity() const
  {
    return Cap;
  }
  constexpr auto
  Size() const
  {
    return mSize;
  }

  void
  push_back(const char ch)
  {
    mArray[mSize++] = ch;
  }

  constexpr auto
  begin() const
  {
    return mArray;
  }

  constexpr auto
  end() const
  {
    return mArray + Size();
  }

  void
  Insert(std::string_view view)
  {
    ASSERT(Size() + view.size() < Capacity(), "No room for string");
    std::memcpy(mArray + Size(), view.data(), view.size());
    mSize += view.size();
  }

  // Joins two strings together, adding a '/' between them. Used for cases where the string is a path-like
  void
  JoinPath(std::string_view prefix, std::string_view suffix)
  {
    Insert(prefix);
    mArray[mSize++] = '/';
    Insert(suffix);
  }

  bool
  IsRelativePath() const noexcept
  {
    return findAdjacentDots(mArray, Size()).has_value();
  }

  std::filesystem::path
  NormalizedPath() const noexcept
  {
    if (IsRelativePath()) {
      return std::filesystem::path{mArray, mArray + Size()}.lexically_normal();
    }
    return std::filesystem::path{mArray, mArray + Size()};
  }

  void
  Clear() noexcept
  {
    mSize = 0;
  }

  std::string_view
  StringView() const noexcept
  {
    return std::string_view{mArray, mSize};
  }

  std::string
  HeapClone(u32 additionalSpace) noexcept
  {
    std::string res;
    res.reserve(Size() + additionalSpace);
    std::copy(mArray, mArray + Size(), std::back_inserter(res));
    return res;
  }

private:
  template <u32 Sz>
  std::optional<u32>
  findAdjacentDots(const char (&str)[Sz], size_t len)
  {
    static_assert(Sz >= 32, "Size must be larger than 32 bytes to use AVX");
    const __m256i dot = _mm256_set1_epi8('.'); // Set up a vector with all '.'

    u32 i = 0;
    for (; i + 31 < len; i += 32) {
      // Load 32 bytes from the string into an AVX2 register
      __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(str + i));

      // Compare each byte in the chunk to '.'
      __m256i cmp = _mm256_cmpeq_epi8(chunk, dot);

      // Move the comparison result to a bitmask
      int mask = _mm256_movemask_epi8(cmp);

      // Check for adjacent dots using the bitmask
      int adjacencyMask = mask & (mask >> 1);
      if (adjacencyMask != 0) {
        // built in pop-count like function, checks trailing zeros
        // and the positions with 1's are where we've actually found ".."
        int pos = __builtin_ctz(adjacencyMask);
        return i + static_cast<u32>(pos);
      }
    }

    // Handle remaining characters if the length is not a multiple of 32
    for (; i + 1 < len; ++i) {
      if (str[i] == '.' && str[i + 1] == '.') {
        return i;
      }
    }

    return std::nullopt; // No adjacent dots found
  }

  u32 mSize{0};
  char mArray[Cap];
};
} // namespace utils
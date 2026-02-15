/** LICENSE TEMPLATE */
#pragma once
#include "../common.h"
#include "utils/expected.h"
#include <common/typedefs.h>
#include <fcntl.h>
#include <filesystem>
#include <sys/mman.h>

namespace mdb {
using Path = std::filesystem::path;

struct ConnectError
{

  enum class Kind
  {
    GetAddressInfo,
    Socket,
    Connect
  };

  Kind kind;
  std::string msg;
  int sys_errno;

  static ConnectError
  AddrInfo(int sys)
  {
    return ConnectError{ .kind = Kind::GetAddressInfo, .msg = "getaddrinfo failed", .sys_errno = sys };
  }

  static ConnectError
  Socket(int sys) noexcept
  {
    return ConnectError{ .kind = Kind::Socket, .msg = "Failed to open socket", .sys_errno = sys };
  }

  static ConnectError
  Connect(const std::string &host, int port, int sys) noexcept
  {
    return ConnectError{
      .kind = Kind::Connect, .msg = std::format("Failed to connect to {}:{}", host, port), .sys_errno = sys
    };
  }
};

template <typename T> struct MemoryMapping
{
  int mFd;
  size_t mFileSize;
  size_t mMapSize;
  void *mMemoryMap;

  ~MemoryMapping() noexcept
  {
    if (mMemoryMap) {
      munmap(mMemoryMap, mFileSize);
    }
  }

  [[nodiscard]] bool
  IsOpen() const
  {
    return mMemoryMap != nullptr;
  }

  [[nodiscard]] size_t
  FileContentsLength() const
  {
    return mFileSize;
  }

  T *
  Data() const
  {
    return (T *)mMemoryMap;
  }

  template <typename U>
  U *
  Cast() const
  {
    return (U *)mMemoryMap;
  }
};

class ScopedFd
{
public:
  ScopedFd() noexcept;
  ScopedFd(int fd) noexcept;
  ScopedFd(int fd, Path p) noexcept;
  ScopedFd &operator=(ScopedFd &&other) noexcept;
  ScopedFd(ScopedFd &&) noexcept;
  ~ScopedFd() noexcept;

  int Get() const noexcept;
  bool IsOpen() const noexcept;
  void Close() noexcept;
  operator int() const noexcept;
  u64 FileSize() const noexcept;
  const Path &GetPath() const noexcept;
  void Release() noexcept;

  template <typename T>
  T *
  MmapFile(std::optional<u64> opt_size, bool read_only) noexcept
  {
    MDB_ASSERT(IsOpen(), "Backing file not open: {}", GetPath().c_str());
    const auto size = opt_size.value_or(FileSize());
    T *ptr = (T *)mmap(nullptr, size, read_only ? PROT_READ : PROT_READ | PROT_WRITE, MAP_PRIVATE, Get(), 0);
    MDB_ASSERT(
      (void *)ptr != MAP_FAILED, "Failed to mmap buffer of size {} from file {}", size, GetPath().c_str());
    return ptr;
  }

  template <typename T>
  MemoryMapping<T>
  MemoryMap(std::optional<u64> optionalSize = std::nullopt, bool read_only = true) const noexcept
  {
    MDB_ASSERT(IsOpen(), "Backing file not open: {}", GetPath().c_str());
    const auto size = optionalSize.value_or(FileSize());
    const auto mapSize = std::max<u64>(size / PAGE_SIZE, 1) * PAGE_SIZE;
    T *ptr = (T *)mmap(nullptr, mapSize, read_only ? PROT_READ : PROT_READ | PROT_WRITE, MAP_PRIVATE, Get(), 0);
    return MemoryMapping<T>{ mFd, size, mapSize, ptr };
  }

  static ScopedFd Open(const Path &p, int flags = O_RDONLY, mode_t mode = mode_t{ 0 }) noexcept;
  static ScopedFd Open(std::string_view path, int flags = O_RDONLY, mode_t mode = mode_t{ 0 }) noexcept;
  static mdb::Expected<ScopedFd, ConnectError> OpenSocketConnectTo(const std::string &host, int port) noexcept;
  static ScopedFd OpenFileReadOnly(const Path &p) noexcept;
  static ScopedFd TakeFileDescriptorOwnership(int fd) noexcept;

private:
  int mFd;
  Path mPath;
  std::optional<u64> mFileSize;
};
} // namespace mdb
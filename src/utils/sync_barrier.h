/** LICENSE TEMPLATE */
#pragma once
#include <common/macros.h>
#include <memory>

namespace mdb {
struct ReadEnd
{
  int fd;
  int read(void *buf, std::size_t bytes) noexcept;
};

struct WriteEnd
{
  int fd;
  int write(const void *buf, std::size_t bytes) noexcept;
};

struct Pipe
{
  ReadEnd read_end;
  WriteEnd write_end;

  int read(void *buf, std::size_t bytes) noexcept;
  int write(const void *buf, std::size_t bytes) noexcept;
  void close() noexcept;
};

Pipe create_pipe() noexcept;

// An actual, safe synchronization barrier, that unlike std::condition_variable, has no weird edge cases, because
// it's 100% dependong on OS-calls (reads and writes that are blocking). This makes this synchronization barrier
// time independent.

// With a normal std::condition_variable, you have the problem that someone might notify that cv, *before* you
// actually get to wait on it

class BarrierWait;
class BarrierNotify;

class Barrier
{
public:
  NO_COPY(Barrier);
  Barrier(Pipe pipe) noexcept;
  ~Barrier() noexcept;

private:
  Pipe pipe;
  std::shared_ptr<Barrier> create_shared() noexcept;
};

class BarrierWait
{
  std::shared_ptr<Barrier> barrier;

public:
  void wait();
};

class BarrierNotify
{
  std::shared_ptr<Barrier> barrier;

public:
  void notify();
};

} // namespace mdb
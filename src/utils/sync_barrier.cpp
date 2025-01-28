/** LICENSE TEMPLATE */
#include "sync_barrier.h"
#include "common.h"
#include <cstring>
#include <fcntl.h>

namespace mdb {
int
ReadEnd::read(void *buf, std::size_t bytes) noexcept
{
  return ::read(fd, buf, bytes);
}

int
WriteEnd::write(const void *buf, std::size_t bytes) noexcept
{
  return ::write(fd, buf, bytes);
}

int
Pipe::read(void *buf, std::size_t bytes) noexcept
{
  return read_end.read(buf, bytes);
}

int
Pipe::write(const void *buf, std::size_t bytes) noexcept
{
  return write_end.write(buf, bytes);
}

void
Pipe::close() noexcept
{
  auto r = ::close(read_end.fd);
  auto w = ::close(write_end.fd);
  ASSERT(r != -1 && w != -1, "Failed to close pipe");
}

Pipe
create_pipe() noexcept
{
  int notify_pipe[2];
  VERIFY(::pipe(notify_pipe) != -1, "Failed to set up notifier pipe {}", strerror(errno));
  return Pipe{.read_end = {notify_pipe[0]}, .write_end = {notify_pipe[1]}};
}

Barrier::Barrier(Pipe pipe) noexcept : pipe(pipe) {}

Barrier::~Barrier() noexcept { pipe.close(); }

std::shared_ptr<Barrier>
Barrier::create_shared() noexcept
{
  return std::make_shared<Barrier>(create_pipe());
}

} // namespace mdb
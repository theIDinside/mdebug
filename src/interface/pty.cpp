#include "pty.h"
#include "../common.h"
#include <asm-generic/ioctls.h>
#include <cstdlib>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

std::optional<MasterPty>
open_pty_master() noexcept
{
  const auto master_fd = posix_openpt(O_RDWR | O_NOCTTY);
  VERIFY(master_fd != -1, "Failed to open PTY");
  VERIFY(grantpt(master_fd) != -1, "Failed to grant access to slave pty");
  VERIFY(unlockpt(master_fd) != -1, "failed to unlock slave pty");
  std::string pty_name = ptsname(master_fd);
  VERIFY(!pty_name.empty(), "Failed to get name of Master PTY");

  return MasterPty{.name = pty_name, .fd = master_fd};
}

std::variant<pid_t, PtyParentResult>
pty_fork(const termios *slave_termios, const winsize *slave_winsize)
{
  const auto mfd_res = open_pty_master();
  VERIFY(mfd_res.has_value(), "Failed to open Master PTY");
  auto [name, fd] = mfd_res.value();

  auto child_pid = fork();

  if (child_pid != 0) {
    return PtyParentResult{.pty_name = name, .pid = child_pid, .fd = fd};
  }

  VERIFY(setsid() != -1, "Failed to setsid in child");

  auto slave_fd = open(name.c_str(), O_RDWR);
  VERIFY(slave_fd != -1, "Failed to open slave pty in child");

#if defined(TIOCSCTTY)
  VERIFY(ioctl(slave_fd, TIOCSCTTY, 0) != -1, "Failed to set TIOCSCTTY on slave fd");
#endif
  if (slave_termios != nullptr) {
    VERIFY(tcsetattr(slave_fd, TCSANOW, slave_termios) != -1, "Failed to set TCSANOW on slave termios");
  }
  if (slave_winsize != nullptr) {
    VERIFY(ioctl(slave_fd, TIOCSWINSZ, slave_winsize) != -1, "Failed to ioctl TIOCSWINSZ on slave window size");
  }

  // Take control of STDIO on the child
  VERIFY(dup2(slave_fd, STDIN_FILENO) == STDIN_FILENO, "failed to dup2 over stdin");
  VERIFY(dup2(slave_fd, STDOUT_FILENO) == STDOUT_FILENO, "failed to dup2 over stdin");
  VERIFY(dup2(slave_fd, STDERR_FILENO) == STDERR_FILENO, "failed to dup2 over stdin");

  if (slave_fd > STDERR_FILENO) {
    close(slave_fd);
  }
  return 0;
}
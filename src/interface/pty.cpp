/** LICENSE TEMPLATE */
#include "pty.h"
#include "../common.h"
#include <asm-generic/ioctls.h>
#include <cstdlib>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
namespace mdb {
std::optional<MasterPty>
open_pty_master() noexcept
{
  const auto masterFile = posix_openpt(O_RDWR | O_NOCTTY);
  VERIFY(masterFile != -1, "Failed to open PTY");
  VERIFY(grantpt(masterFile) != -1, "Failed to grant access to slave pty");
  VERIFY(unlockpt(masterFile) != -1, "failed to unlock slave pty");
  std::string pty_name = ptsname(masterFile);
  VERIFY(!pty_name.empty(), "Failed to get name of Master PTY");

  return MasterPty{.mName = pty_name, .mFd = masterFile};
}

std::variant<pid_t, PtyParentResult, ParentResult>
ptyFork(bool dontDuplicateStdio, const termios *slaveTermios, const winsize *slave_winsize)
{
  if (dontDuplicateStdio) {
    auto childPid = fork();

    if (childPid != 0) {
      return ParentResult{.mChildPid = childPid};
    } else {
      return 0;
    }
  }
  const auto masterFileDescriptorResult = open_pty_master();
  VERIFY(masterFileDescriptorResult.has_value(), "Failed to open Master PTY");
  auto [name, fd] = masterFileDescriptorResult.value();

  auto childPid = fork();

  if (childPid != 0) {
    return PtyParentResult{.mPtyName = name, .mPid = childPid, .mFd = fd};
  }

  VERIFY(setsid() != -1, "Failed to setsid in child");

  auto slaveFd = open(name.c_str(), O_RDWR);
  VERIFY(slaveFd != -1, "Failed to open slave pty in child");

#if defined(TIOCSCTTY)
  VERIFY(ioctl(slaveFd, TIOCSCTTY, 0) != -1, "Failed to set TIOCSCTTY on slave fd");
#endif
  if (slaveTermios != nullptr) {
    VERIFY(tcsetattr(slaveFd, TCSANOW, slaveTermios) != -1, "Failed to set TCSANOW on slave termios");
  }

  if (slave_winsize != nullptr) {
    VERIFY(ioctl(slaveFd, TIOCSWINSZ, slave_winsize) != -1, "Failed to ioctl TIOCSWINSZ on slave window size");
  }

  // Take control of STDIO on the child
  VERIFY(dup2(slaveFd, STDIN_FILENO) == STDIN_FILENO, "failed to dup2 over stdin");
  VERIFY(dup2(slaveFd, STDOUT_FILENO) == STDOUT_FILENO, "failed to dup2 over stdin");
  VERIFY(dup2(slaveFd, STDERR_FILENO) == STDERR_FILENO, "failed to dup2 over stdin");

  if (slaveFd > STDERR_FILENO) {
    close(slaveFd);
  }
  return 0;
}
} // namespace mdb
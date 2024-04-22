#include "gdb_remote_commander.h"
#include "common.h"

namespace tc {

/*static*/
std::unique_ptr<TraceeCommandInterface>
GdbRemoteCommander::createConnection(const GdbRemoteCfg &config) noexcept
{
  TODO_FMT("Remote: {}:{} - Implement construction of interface, connection to remote server and initialization "
           "of interface",
           config.host, config.port);
  return nullptr;
}

} // namespace tc

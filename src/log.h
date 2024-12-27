#pragma once

namespace mdb {
namespace log {

class Config
{
public:
  static bool &
  LogTaskGroup()
  {
    static bool globalLogTaskGroup = true; // Lazily initialized global bool
    return globalLogTaskGroup;
  }

  static void
  SetLogTaskGroup(bool configure = true)
  {
    LogTaskGroup() = configure;
  }
};

}; // namespace log
} // namespace mdb
#include "type.h"
#include <filesystem>

Path
File::dir() const noexcept
{
  Path p{name};
  return p.root_directory();
}
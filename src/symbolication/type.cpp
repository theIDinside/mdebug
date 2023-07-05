#include "type.h"
#include <filesystem>

Path
CompilationUnitFile::dir() const noexcept
{
  Path p{name};
  return p.root_directory();
}

Path
CompilationUnitFile::source_filename() const noexcept
{
  Path p{name};
  return p.filename();
}
#include "so_loading.h"
#include "common.h"
#include "symbolication/elf.h"
#include <filesystem>

SharedObject::SharedObject(TPtr<link_map> tloc, AddrPtr addr, Path &&path) noexcept
    : tracee_location(tloc), elf_vma_addr_diff(addr), path(std::move(path)), so_name(path.filename())
{
}

std::string_view
SharedObject::name() const noexcept
{
  return so_name;
}

Path
interpreter_path(ElfSection *interp) noexcept
{
  ASSERT(interp->get_name() == ".interp", "Section is not .interp: {}", interp->get_name());
  DwarfBinaryReader reader{interp->data(), interp->size()};
  const auto path = reader.read_string();
  DLOG("mdb", "Path to system interpreter: {}", path);
  return path;
}

void
SharedObjectMap::add_if_new(TPtr<link_map> tracee_location, AddrPtr elf_diff, Path &&path) noexcept
{
  auto it = find(shared_objects, [&p = path](const auto &so) { return so.path == p; });
  if (it == std::end(shared_objects)) {
    DLOG("mdb", "New shared object read: {}", path.c_str());
    shared_objects.push_back(SharedObject{tracee_location, elf_diff, std::move(path)});
  }
}
#include "so_loading.h"
#include "symbolication/block.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
#include <common.h>
#include <filesystem>

SharedObject::SharedObject(int so_id, TPtr<link_map> tloc, AddrPtr addr, Path &&path) noexcept
    : so_id(so_id), tracee_location(tloc), elf_vma_addr_diff(addr), path(std::move(path)),
      so_name(this->path.filename()), symbol_info(SharedObjectSymbols::None), objfile(nullptr)
{
  addr_range.low = addr;
}

std::string_view
SharedObject::name() const noexcept
{
  return so_name;
}

AddressRange
SharedObject::relocated_addr_range() const noexcept
{
  return addr_range;
}

Path
SharedObject::symbol_file_path() const noexcept
{
  return path;
}

std::optional<bool>
SharedObject::is_optimized() const noexcept
{
  DLOG("mdb", "Knowing if SO is optimized is not implemented");
  return std::nullopt;
}

std::optional<std::string>
SharedObject::version() const noexcept
{
  return std::nullopt;
}

ObjectFile *
SharedObject::load_objectfile() noexcept
{
  if (objfile)
    return objfile;

  if (!std::filesystem::exists(path))
    return nullptr;
  objfile = mmap_objectfile(path);
  ASSERT(objfile != nullptr, "Failed to mmap objfile {}", path.c_str());
  return objfile;
}

bool
SharedObject::has_debug_info() const noexcept
{
  if (objfile == nullptr)
    return false;

  return objfile->parsed_elf->get_section(".debug_info") != nullptr;
}

Path
interpreter_path(const Elf *elf, const ElfSection *interp) noexcept
{
  ASSERT(interp->get_name() == ".interp", "Section is not .interp: {}", interp->get_name());
  DwarfBinaryReader reader{elf, interp};
  const auto path = reader.read_string();
  DLOG("mdb", "Path to system interpreter: {}", path);
  return path;
}

std::optional<SharedObject::SoId>
SharedObjectMap::add_if_new(TPtr<link_map> tracee_location, AddrPtr elf_diff, Path &&path) noexcept
{
  auto it = find(shared_objects, [&p = path](const auto &so) { return so.path == p; });
  if (it == std::end(shared_objects)) {
    const auto so_id = next_so_id++;
    shared_objects.push_back(SharedObject{so_id, tracee_location, elf_diff, std::move(path)});
    return so_id;
  }
  return std::nullopt;
}

SharedObject *
SharedObjectMap::get_so(int id) noexcept
{
  for (auto &so : shared_objects) {
    if (so.so_id == id)
      return &so;
  }
  return nullptr;
}
/** LICENSE TEMPLATE */
#include "so_loading.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/elf.h"
#include "symbolication/objfile.h"
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
  DBGLOG(core, "Knowing if SO is optimized is not implemented");
  return std::nullopt;
}

std::optional<std::string>
SharedObject::version() const noexcept
{
  return std::nullopt;
}

bool
SharedObject::has_debug_info() const noexcept
{
  if (objfile == nullptr) {
    return false;
  }
  return objfile->GetElf()->GetSection(".debug_info") != nullptr;
}

SharedObject
SharedObject::clone() const noexcept
{
  auto path_copy = path;
  SharedObject clone{so_id, tracee_location, elf_vma_addr_diff, std::move(path_copy)};
  clone.addr_range = addr_range;
  clone.objfile = objfile;
  clone.symbol_info = clone.symbol_info;

  return clone;
}

Path
interpreter_path(const Elf *elf, const ElfSection *interp) noexcept
{
  ASSERT(interp->mName == ".interp", "Section is not .interp: {}", interp->mName);
  DwarfBinaryReader reader{elf, interp->mSectionData};
  const auto path = reader.read_string();
  DBGLOG(core, "Path to system interpreter: {}", path);
  return path;
}

SharedObjectMap
SharedObjectMap::clone() const noexcept
{
  SharedObjectMap clone{};
  clone.shared_objects.reserve(shared_objects.size());
  for (const auto &so : shared_objects) {
    clone.shared_objects.push_back(so.clone());
  }

  return clone;
}

std::optional<SharedObject::SoId>
SharedObjectMap::add_if_new(TPtr<link_map> tracee_location, AddrPtr elf_diff, Path &&path) noexcept
{
  DBGLOG(core, "Shared object {}; elf diff = {}", path.c_str(), elf_diff);
  auto it = find(shared_objects, [&p = path](const auto &so) { return so.path == p; });
  if (it == std::end(shared_objects)) {
    const auto so_id = new_id();
    shared_objects.push_back(SharedObject{so_id, tracee_location, elf_diff, std::move(path)});
    return so_id;
  }
  return std::nullopt;
}

SharedObject *
SharedObjectMap::get_so(int id) noexcept
{
  for (auto &so : shared_objects) {
    if (so.so_id == id) {
      return &so;
    }
  }
  return nullptr;
}

int
SharedObjectMap::new_id() noexcept
{
  const auto it = next_so_id;
  ++next_so_id;
  return it;
}
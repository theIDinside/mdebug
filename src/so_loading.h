#pragma once
#include "common.h"
#include "link.h"
#include "symbolication/block.h"
#include "utils/macros.h"
#include <array>

struct ObjectFile;
struct ElfSection;
class Elf;

constexpr std::array<std::string_view, 6> LOADER_SYMBOL_NAMES = {
  "r_debug_state",      "_r_debug_state",          "_dl_debug_state",
  "rtld_db_dlactivity", "__dl_rtld_db_dlactivity", "_rtld_debug_state",
};

constexpr std::string_view LOADER_STATE = "_r_debug_extended";

enum class SharedObjectSymbols : u8
{
  Minimum,
  Full,
  None,
};

constexpr auto
so_sym_info_description(SharedObjectSymbols sos)
{
  switch (sos) {
  case SharedObjectSymbols::Minimum:
    return "Minimal symbols loaded";
  case SharedObjectSymbols::Full:
    return "DWARF & Minimal symbols loaded";
  case SharedObjectSymbols::None:
    return "No symbols loaded";
  }
  MIDAS_UNREACHABLE
}

struct SharedObject
{
  NO_COPY(SharedObject);
  using SoId = int;
  SharedObject(int so_id, TPtr<link_map> tracee_loc, AddrPtr elf_addr_diff, Path &&path) noexcept;
  SharedObject(SharedObject &&) noexcept = default;
  SharedObject &operator=(SharedObject &&) = default;
  std::string_view name() const noexcept;
  AddressRange relocated_addr_range() const noexcept;
  Path symbol_file_path() const noexcept;
  std::optional<bool> is_optimized() const noexcept;
  std::optional<std::string> version() const noexcept;

  bool has_debug_info() const noexcept;

public:
  int so_id;
  TPtr<link_map> tracee_location;
  AddrPtr elf_vma_addr_diff;
  Path path;
  std::string so_name;
  SharedObjectSymbols symbol_info;
  AddressRange addr_range;
  ObjectFile *objfile;
};

class SharedObjectMap
{
public:
  SharedObjectMap() = default;
  std::optional<SharedObject::SoId> add_if_new(TPtr<link_map> tracee_location, AddrPtr elf_diff,
                                               Path &&path) noexcept;

  // Do not hold on to this pointer as it may or may not be long lived (due to re-allocation).
  SharedObject *get_so(int id) noexcept;

private:
  std::vector<SharedObject> shared_objects;
  int new_id() noexcept;
  int next_so_id;
};

Path interpreter_path(const Elf *elf, const ElfSection *interp) noexcept;
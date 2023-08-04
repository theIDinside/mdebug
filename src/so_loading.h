#pragma once
#include "common.h"
#include "link.h"
#include <array>

struct ElfSection;

constexpr std::array<std::string_view, 6> LOADER_SYMBOL_NAMES = {
    "r_debug_state",      "_r_debug_state",          "_dl_debug_state",
    "rtld_db_dlactivity", "__dl_rtld_db_dlactivity", "_rtld_debug_state",
};

constexpr std::string_view LOADER_STATE = "_r_debug_extended";

struct SharedObject
{
  NO_COPY(SharedObject);

  SharedObject(TPtr<link_map> tracee_loc, AddrPtr elf_addr_diff, Path &&path) noexcept;
  SharedObject(SharedObject &&) noexcept = default;
  SharedObject &operator=(SharedObject &&) = default;
  std::string_view name() const noexcept;

public:
  TPtr<link_map> tracee_location;
  AddrPtr elf_vma_addr_diff;
  Path path;
  std::string so_name;
};

class SharedObjectMap
{
public:
  SharedObjectMap() = default;
  void add_if_new(TPtr<link_map> tracee_location, AddrPtr elf_diff, Path &&path) noexcept;

private:
  std::vector<SharedObject> shared_objects;
};

Path interpreter_path(ElfSection *interp) noexcept;
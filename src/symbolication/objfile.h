#pragma once
#include "../common.h"
#include <sys/mman.h>

class Elf;

/**
 * The owning data-structure that all debug info symbols point to. The ObjFile is meant
 * to outlive them all, so it's safe to take raw pointers into `loaded_binary`.
 */
struct ObjectFile
{
  ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept;
  ~ObjectFile() noexcept;
  Path path;
  u64 size;
  const u8 *loaded_binary;

  TPtr<void> entry_point;

  template <typename T>
  T *
  get_at(u64 offset)
  {
    return (T *)(loaded_binary + offset);
  }

  u64 get_offset(u8 *ptr) const noexcept;
  u8 *get_section(Elf *elf, u32 index) const noexcept;
};

struct UnloadObjectFile
{
  void
  operator()(ObjectFile *obj)
  {
    munmap((void *)obj->loaded_binary, obj->size);
    obj->loaded_binary = nullptr;
    obj->size = 0;
    obj->path = "";
  }
};

void object_file_unloader(ObjectFile *obj);
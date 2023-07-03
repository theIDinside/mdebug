#include "objfile.h"

ObjectFile::ObjectFile(Path p, u64 size, const u8 *loaded_binary) noexcept
    : path(std::move(p)), size(size), loaded_binary(loaded_binary), entry_point(), vm_text_section()
{
  ASSERT(size > 0, "Loaded Object File is invalid");
}

ObjectFile::~ObjectFile() noexcept { munmap((void *)loaded_binary, size); }

u64
ObjectFile::get_offset(u8 *ptr) const noexcept
{
  ASSERT(ptr > loaded_binary, "Attempted to take address before {:p} with {:p}", (void *)loaded_binary,
         (void *)ptr);
  ASSERT((u64)(ptr - loaded_binary) < size, "Pointer is outside of bounds of 0x{:x} .. {:x}",
         (std::uintptr_t)loaded_binary, (std::uintptr_t)(loaded_binary + size))
  return ptr - loaded_binary;
}

TPtr<void> ObjectFile::text_section_offset() const noexcept {
  return nullptr;
}
#include <cstdint>
#include <iostream>
#include <sys/mman.h>

using u8 = std::uint8_t;

int
main()
{
  std::uintptr_t addr = 0x1f21000;
  auto page = (u8 *)mmap((void *)addr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    std::cout << "failed to mmap at " << addr << "\n";
    perror("error: ");
    exit(-1);
  } else if (page != (u8 *)addr) {
    perror("failed to map page in at desired address");
    exit(-1);
  }

  auto write_pointer = page;
  for (u8 i = 0; i < 255; ++i) {
    *write_pointer = i;
    ++write_pointer;
  }

  std::cout << "written all numbers between 0 .. 255 now to page. You should set a bp here." << std::endl; // BP1
}
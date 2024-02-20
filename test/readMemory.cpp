#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/mman.h>

void
stack()
{
  uint8_t a = 0x11;
  uint8_t b = 0x22;
  uint8_t c = 0x33;
  uint8_t d = 0x44;
  uint8_t e = 0x55;
  uint8_t f = 0x66;
  uint8_t g = 0x77;
  uint8_t h = 0x88;
  int j = 0xff'ff'ff'ff; // BP2
}
struct ArrType
{
  int a;
  float b;
};

int
main()
{
  ArrType array[60]{
      {0, 0.00},   {1, 1.01},   {2, 2.02},   {3, 3.03},   {4, 4.04},   {5, 5.05},   {6, 6.06},   {7, 7.07},
      {8, 8.08},   {9, 9.09},   {10, 10.10}, {11, 11.11}, {12, 12.12}, {13, 13.13}, {14, 14.14}, {15, 15.15},
      {16, 16.16}, {17, 17.17}, {18, 18.18}, {19, 19.19}, {20, 20.20}, {21, 21.21}, {22, 22.22}, {23, 23.23},
      {24, 24.24}, {25, 25.25}, {26, 26.26}, {27, 27.27}, {28, 28.28}, {29, 29.29}, {30, 30.30}, {31, 31.31},
      {32, 32.32}, {33, 33.33}, {34, 34.34}, {35, 35.35}, {36, 36.36}, {37, 37.37}, {38, 38.38}, {39, 39.39},
      {40, 40.40}, {41, 41.41}, {42, 42.42}, {43, 43.43}, {44, 44.44}, {45, 45.45}, {46, 46.46}, {47, 47.47},
      {48, 48.48}, {49, 49.49}, {50, 50.50}, {51, 51.51}, {52, 52.52}, {53, 53.53}, {54, 54.54}, {55, 55.55},
      {56, 56.56}, {57, 57.57}, {58, 58.58}, {59, 59.59},
  };
  std::uintptr_t addr = 0x1f21000; // ARRBP
  auto page = (std::uint8_t *)mmap((void *)addr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    std::cout << "failed to mmap at " << addr << "\n";
    perror("error: ");
    exit(-1);
  } else if (page != (std::uint8_t *)addr) {
    perror("failed to map page in at desired address");
    exit(-1);
  }

  auto write_pointer = page;
  for (std::uint8_t i = 0; i < 255; ++i) {
    *write_pointer = i;
    ++write_pointer;
  }

  const char *hello_world = "hello world";
  unsigned char *str_ptr = page + (4096 - std::strlen(hello_world) + 3);
  auto len = std::strlen(hello_world) - 3;
  for (auto i = 0; i < len; ++i) {
    *(str_ptr + i) = hello_world[i];
  }

  std::cout << "written all numbers between 0 .. 255 now to page. You should set a bp here." << std::endl; // BP1
  stack();
}
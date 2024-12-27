#include <iostream>
#include <memory_resource>
#include <format>

int main() {
  std::array<char, 32> buf;
  std::pmr::monotonic_buffer_resource rsrc{&buf, std::size(buf), std::pmr::new_delete_resource() };
  std::pmr::string test{&rsrc};
  test.reserve(4);
  test.append("hell");
  test.append("o world");
  test.append("what's going on");
  std::print(std::cout, "data:\t\t 0x{}\n", (void*)test.data());
  std::print(std::cout, "array data:\t 0x{}\n Now add additional data, and hopefully we get from new and delete\n", (void*)buf.data());

  test.append("this is yet another string, let's see what happens");
  
  std::print(std::cout, "data: 0x{}\n", (void*)test.data());
  std::print(std::cout, "array data: 0x{}\n", (void*)buf.data());

  std::print(std::cout, "array contents: \t '{}'\n", std::string_view{buf.data(), 32});

  return 0;
}

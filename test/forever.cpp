#include <chrono>
#include <iostream>
#include <thread>

int
main(int argc, const char **argv)
{
  auto tid = gettid();
  while (true) {
    std::cout << tid << " is sleeping for 1 sec..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds{1000});
  }
}
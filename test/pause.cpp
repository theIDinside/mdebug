#include <iostream>
#include <unistd.h>
int
main(int argc, const char **argv)
{
  std::cout << "going to sleep" << std::endl;
  sleep(10); // SLEEPLINE
  std::cout << "woke up" << std::endl;
}
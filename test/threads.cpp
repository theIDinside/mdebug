#include <thread>
#include <vector>
#include <cstdio>
#include <mutex>
#include <linux/sched.h>


using ThreadPool = std::vector<std::thread>;

int main(int argc, const char**) {

  int a = 10 + argc;
  int b = a * 9;
  printf("b: %d\n", b);

  ThreadPool thread_pool;

  for(auto i = 0; i < 8; i++) {
    thread_pool.push_back(std::thread{[index = i](){
      return index * 1000;
    }});
  }

  for(auto&& thread : thread_pool) {
      thread.join();
      printf("Thread joined...\n");
  }
}
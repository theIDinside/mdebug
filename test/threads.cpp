#include "dynamic_lib.h"
#include "spinlock.hpp"
#include <algorithm>
#include <cstdio>
#include <linux/sched.h>
#include <mutex>
#include <numeric>
#include <thread>
#include <vector>

using ThreadPool = std::vector<std::thread>;

int
main(int argc, const char **)
{

  Foo foo{};
  foo.a = 1;
  foo.b = 2;
  foo.c = 3;
  foo.d = 4;

  SpinLock spin_lock{};

  static int ids[8]{-1, -1, -1, -1, -1, -1, -1, -1};
  int a = 10 + argc;
  int b = a * 9;
  printf("b: %d\n", b);

  float degC = 25;
  float degF;
  degF = convert_celsius_to_fahrenheit(degC);
  printf("%.0f degrees Celsius equals %.0f degrees Fahrenheit\n", degC, degF);

  ThreadPool thread_pool;

  for (auto i = 0; i < 8; i++) {
    thread_pool.push_back(std::thread{[i, &foo, &spin_lock]() {
      auto pos = i / 2 % 4;
      for (auto j = 0; j < 1000; j++) {
        if (pos == 0) {
          spin_lock.lock();
          foo.a++;
          spin_lock.unlock();
        } else if (pos == 1) {
          spin_lock.lock();
          foo.b++;
          spin_lock.unlock();
        } else if (pos == 2) {
          spin_lock.lock();
          foo.c++;
          spin_lock.unlock();
        } else if (pos == 3) {
          spin_lock.lock();
          foo.d++;
          spin_lock.unlock();
        }
      }
      spin_lock.lock();
      for (auto idx = 0; idx < 8; idx++) {
        if (ids[idx] == -1) {
          ids[idx] = i;
          float degF;
          degF = convert_celsius_to_fahrenheit(foo.c);
          printf("%.0f degrees Celsius equals %.0f degrees Fahrenheit\n", foo.c, degF);
          break;
        }
      }
      spin_lock.unlock();
    }});
  }

  auto done_list_index = 0;
  while (done_list_index < 8) {
    if (ids[done_list_index] != -1) {
      thread_pool[ids[done_list_index]].join();
      done_list_index++;
    }
  }

  printf("Thread joined order:\n");
  for (auto id : ids) {
    printf("%d\n", id);
  }
  printf("Foo {a: %d, b: %lld, c: %f, d: %f}", foo.a, foo.b, foo.c, foo.d);
}
#pragma once
#include <atomic>
#include <ctime>

class SpinLock {
public:
  SpinLock();
  void lock() noexcept;
  void unlock() noexcept;
private:
  std::atomic<unsigned int> m_flag;
};

template <typename T>
struct IntrusiveList {
  T* next;
  T* prev;
};

struct Foo : IntrusiveList<Foo> {
  int a;
  long long b;
  float c;
  double d;
};
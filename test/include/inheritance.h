#pragma once

class ParentA
{
public:
  ParentA(int a) noexcept : a(a) {}
  ~ParentA() noexcept = default;

protected:
  int a;
};

class ParentB
{
public:
  ParentB(int a, int b) noexcept : a(a), b(b) {}
  ~ParentB() noexcept = default;

protected:
  int a;
  int b;
};

class Derived : ParentA, ParentB
{
public:
  Derived(int aa, int ba, int bb) : ParentA(aa), ParentB(ba, bb) {}
};
#pragma once

class TestObject
{
  int a, b;

public:
  TestObject(int a_param, int b_param) noexcept;
  bool _less_than() noexcept;
  bool _greater_than() noexcept;
  bool _equals() noexcept;
};
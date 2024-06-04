#include <array>
#include <people.h>

void
stdlib_arr_ptrs()
{
  int arr_a[3]{1, 2, 3};
  int arr_b[3]{10, 20, 30};
  int arr_c[3]{100, 200, 300};

  std::array<int[3], 3> arr_of_arrs = std::array<int[3], 3>({{1, 2, 3}, {10, 20, 30}, {100, 200, 300}});
}

int
ptr_int_ptr_(int **ptrs, std::size_t count)
{
  int res = 0;
  for (auto i = 0; i < count; ++i) {
    auto ptr = ptrs[i];
    ++ptr;
    const int value = *ptr; // #PTR_INT_PTR_LOAD_PTR_BP
    res += value;           // #PTR_INT_PTR_LOAD_VALUE
  }
  return res; // #PTR_INT_PTR_RET_BP
}

int
ptr_int_ptr()
{
  const auto sz = 5;
  int *intsA = new int[sz];
  int *intsB = new int[sz];
  int *intsC = new int[sz];
  for (auto i = 0; i < sz; ++i) {
    intsA[i] = i;
    intsB[i] = i * 10;
    intsC[i] = i * 100;
  }
  auto ptrs_to_ptrs = new int *[3];
  ptrs_to_ptrs[0] = intsA;
  ptrs_to_ptrs[1] = intsB;
  ptrs_to_ptrs[2] = intsC;
  ptr_int_ptr_(ptrs_to_ptrs, 3);

  return 1;
}

int
person_ptr()
{
  Person *john = new Person{1, 42, "John Doe"};
  Person *jane = new Person{2, 34, "Jane Doe"};
  return 1; // #PERSON_PTR_RET_BP
}

int
int_ptr()
{
  int *ptr = new int{10};
  *ptr = 42;       // #INT_PTR_STORE_BP
  int read = *ptr; // #INT_PTR_LOAD_BP
  return read;     // #INT_PTR_RET_BP
}

int
main()
{
  int_ptr();
  person_ptr();
  ptr_int_ptr();
}
// The third compilation unit that will have a definition of Person, via C/C++ #include

#include "a.h"
#include "b.h"
#include "person.h"

int
main()
{
  Person p{"Luo", "Ji", 1};
  Person p2{"Mike", "Evans", 1};
  Person p3{"Isaac", "Asimof", 3};
  ChangePersonLastName(p3, "Asimov");
  ChangePersonId(p2, 2);
  return 0;
}
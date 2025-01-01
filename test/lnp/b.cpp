#include "b.h"
#include "person.h"

void ChangePersonId(Person& p, int id) noexcept {
    p.mId = id;
}
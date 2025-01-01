#include "a.h"
#include "person.h"

void ChangePersonLastName(Person& p, std::string lastName) noexcept {
    p.mLastName = std::move(lastName);
}
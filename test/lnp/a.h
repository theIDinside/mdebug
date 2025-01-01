#pragma once
#include <string>

// should instantiate a is_declaration DIE in the debug symbol data
struct Person;

void ChangePersonLastName(Person& p, std::string lastName) noexcept;
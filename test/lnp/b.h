#pragma once

// should instantiate a is_declaration DIE in the debug symbol data
struct Person;

void ChangePersonId(Person& p, int id) noexcept;
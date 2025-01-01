#pragma once
#include <string>

// This test subject will include this file in 2 different .cpp files, which should create 2 compilation units in
// debug info Since `Person` is constexpr (and therefore probably inline), we want to determine how and where it's
// represented in debug info. Is it separately and duplicated over the two CU? Is it only in the source file? And
// if so, what should the mapping to the type scaffolding be (a type scaffolding is a type not fully resolved yet)

// What I mean by this, will there be one or multiple Debug Information Entries, with tag `DW_TAG_structured_type`
// | `DW_TAG_class_type`, or just one?

struct Person
{
  constexpr Person(std::string firstName, std::string lastName, int id) noexcept
      : mFirstName(std::move(firstName)), mLastName(std::move(lastName)), mId(id)
  {
  }
  std::string mFirstName;
  std::string mLastName;
  int mId;
};
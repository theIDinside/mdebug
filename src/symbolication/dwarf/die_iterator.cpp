/** LICENSE TEMPLATE */
#include "die_iterator.h"
#include "die.h"

namespace mdb::sym::dw {

/*static*/
const DieMetaData *
DieSiblingIterator::StartDie(const DieMetaData *die) noexcept
{
  return die->Sibling();
}

DieSiblingIterator::DieSiblingIterator(UnitData *cu, const DieMetaData *die) noexcept : cu(cu), die(die) {}

DieSiblingIterator &
DieSiblingIterator::operator++() noexcept
{
  die = die->Sibling();
  return *this;
}

DieSiblingIterator
DieSiblingIterator::operator++(int) noexcept
{
  auto it = *this;
  die = die->Sibling();
  return it;
}

const DieMetaData &
DieSiblingIterator::operator*() const noexcept
{
  return *die;
}

const DieMetaData *
DieSiblingIterator::operator->() const noexcept
{
  return die;
}

const DieMetaData &
DieSiblingIterator::operator*() noexcept
{
  return *die;
}

const DieMetaData *
DieSiblingIterator::operator->() noexcept
{
  return die;
}

} // namespace mdb::sym::dw
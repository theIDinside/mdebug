/** LICENSE TEMPLATE */
#include "die_iterator.h"
#include "die.h"

namespace sym::dw {

/*static*/
const DieMetaData *
DieSiblingIterator::StartDie(const DieMetaData *die) noexcept
{
  return die->sibling();
}

DieSiblingIterator::DieSiblingIterator(UnitData *cu, const DieMetaData *die) noexcept : cu(cu), die(die) {}

DieSiblingIterator &
DieSiblingIterator::operator++() noexcept
{
  die = die->sibling();
  return *this;
}

DieSiblingIterator
DieSiblingIterator::operator++(int) noexcept
{
  auto it = *this;
  die = die->sibling();
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

} // namespace sym::dw
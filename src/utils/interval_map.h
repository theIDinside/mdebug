/** LICENSE TEMPLATE */
#pragma once
#include "util.h"
#include <common.h>

namespace mdb {
template <typename Datum> struct IntervalNodeValue
{
  bool end;
  Datum value;
};

template <typename AddrType>
concept AddressType = requires(AddrType addr) {
  // make sure the AddressType has numeric_limits::max/min specialized for it
  std::numeric_limits<AddrType>::min();
  std::numeric_limits<AddrType>::max();
  // require that it can be compared
  { addr < addr } -> std::convertible_to<bool>;
  { addr > addr } -> std::convertible_to<bool>;
  { addr <= addr } -> std::convertible_to<bool>;
  { addr == addr } -> std::convertible_to<bool>;
};

template <typename Datum, AddressType A> struct IntervalNode
{
  A addr;
  std::vector<IntervalNodeValue<Datum>> values{};
};

/** Container that maps an intervals of `AddressType` to datum/value/objects. It's highly recommended that
 * `MapDatum` is cheap, as this type involves some duplication. So, it's suggested that it should be, perhaps a
 * pointer type or an index type of some sort. The intended initial use for this type is to map `AddrPtr` intervals
 * to `sym::dw::UnitData*` which is cheap. */
template <AddressType A, typename MapDatum> class IntervalMapping
{
public:
  // The default range is 0 .. u64::max which is the entirety of the span of addressable memory (not exactly the
  // truth, but whatever). Inserting these two sentinel values simplifies things alot.
  IntervalMapping() noexcept
      : interval({ IntervalNode<MapDatum, A>{ .addr = std::numeric_limits<A>::min(), .values = {} },
          IntervalNode<MapDatum, A>{ .addr = std::numeric_limits<A>::max(), .values = {} } })
  {
  }

  /**
   * Add the mapping [ `start` .. `end` ] -> `value`, such that any search with keys that range between these two
   * endpoints (inclusively), will return `value`, as well as any other `value` whose range-mapping intersects with
   * the key.
   */
  void
  AddMapping(A start, A end, MapDatum value)
  {
    auto it_a = MaybePartitionAt<EndpointType::Start>(FindIndexOf<false>(start), start);
    auto it_b = MaybePartitionAt<EndpointType::End>(FindIndexOf<false>(end), end);

    for (; it_a < it_b; ++it_a) {
      it_a->values.push_back({ false, value });
    }
    it_a->values.push_back({ true, value });
  }

  /**
   * Find what values have a range that covers `key`. Returns found values. If nothing was found return `None`.
   */
  std::optional<std::vector<MapDatum>>
  Find(A key) const
  {
    auto pos = FindIndexOf<true>(key);
    if (pos == interval.size()) {
      return {};
    } else {
      std::vector<MapDatum> result{};
      auto &node = interval[std::max(static_cast<int>(pos - 1), 0)];
      auto &values = node.values;
      for (const auto &v : values) {
        if (!v.end || key <= node.addr) {
          result.push_back(v.value);
        }
      }
      return result;
    }
  }

  /**
   * Find what values have a range that covers `key` and write the results to `write_to_result`. Returns true iff
   * any values were found, false otherwise.
   */
  constexpr bool
  Find(A key, std::vector<MapDatum> &write_to_result) noexcept
  {
    auto pos = FindIndexOf<true>(key);
    if (pos == interval.size()) {
      return false;
    } else {
      auto &node = interval[std::max(static_cast<int>(pos - 1), 0)];
      auto &values = node.values;
      const auto sz = write_to_result.size();
      for (const auto &v : values) {
        if (!v.end || key <= node.addr) {
          write_to_result.push_back(v.value);
        }
      }
      return sz != write_to_result.size();
    }
  }

private:
  using Container = std::vector<IntervalNode<MapDatum, A>>;
  Container interval;
  enum class EndpointType
  {
    Start,
    End
  };

  constexpr bool
  NodeAddressEquals(size_t index, A addr) noexcept
  {
    // index was produced by not finding a range in the interval container that can fit `addr`, as such it (most
    // likely) points to .size() (i.e. one beyond last). Therefore, also ASSERT on that, lest it be misused (we
    // will then find out if the index value is getting produced in odd ways.)
    if (!(index < interval.size())) {
      MDB_ASSERT(index == interval.size(),
        "unexpected index value has been prodcued: {}, size of interval container: {}",
        index,
        interval.size());
      return false;
    }
    return interval[index].addr == addr;
  }

  constexpr auto
  FindIndexToInsertAt(A pc) const noexcept
  {
    constexpr auto find = [](const IntervalNode<MapDatum, A> &node, auto pc) { return node.addr < pc; };

    auto it = std::lower_bound(interval.begin(), interval.end(), pc, find);
    auto dist = std::distance(interval.begin(), it);
    return dist;
  }

  template <bool AlsoEquals>
  constexpr auto
  FindIndexOf(A pc) const noexcept
  {
    constexpr auto find = [](const IntervalNode<MapDatum, A> &node, auto pc) {
      if constexpr (AlsoEquals) {
        return node.addr <= pc;
      } else {
        return node.addr < pc;
      }
    };

    auto it = std::lower_bound(interval.begin(), interval.end(), pc, find);
    u32 dist = std::distance(interval.begin(), it);
    return dist;
  }

  constexpr auto
  EnsureNoIteratorInvalidation() noexcept
  {
    // Doing this, we can know, that two successive `maybe_partition_at` calls inside
    // `add_mapping` will not have the returned iterators from this function
    // invalidated.
    if ((static_cast<int>(interval.size()) >= (static_cast<int>(interval.capacity()) - 2))) {
      auto new_cap = static_cast<int>(interval.capacity() * 2);
      while (new_cap - interval.capacity() <= 2) {
        new_cap += 2;
      }
      interval.reserve(new_cap);
    }
  }

  /**
   * Partition the range (splits it by inserting a node between the endpoints) that contains `with_addr` and return
   * an iterator to the newly created node. If a node exists with an address = `with_addr`, no partition is
   * performed and an iterator pointing to that node is returned.
   *
   * This function is safe to call twice successively inside of a function, even if both calls allocates new nodes,
   * because it ensures that always at least 2 additional elements can fit in `interval`, making sure that no
   * re-allocation happens (and thus invalidating one or two iterators)
   */
  template <EndpointType type>
  constexpr auto
  MaybePartitionAt(size_t index, A with_addr) noexcept
  {
    if constexpr (type == EndpointType::Start) {
      EnsureNoIteratorInvalidation();
    }

    // a node with this address already exists, no need to partition the range
    // [N .. M] that contains `with_addr`
    if (NodeAddressEquals(index, with_addr)) {
      return interval.begin() + index;
    }

    if constexpr (type == EndpointType::Start) {
      auto it =
        interval.insert(interval.begin() + index, IntervalNode<MapDatum, A>{ .addr = with_addr, .values = {} });
      CopyTo(interval[index - 1].values, it->values);
    } else {
      auto it =
        interval.insert(interval.begin() + index, IntervalNode<MapDatum, A>{ .addr = with_addr, .values = {} });
      if (index < interval.size() - 1) {
        TransformCopyTo(interval[index + 1].values, it->values, [](auto it) {
          auto copy = it;
          copy.end = false;
          return copy;
        });
      }
    }
    return interval.begin() + index;
  }
};

} // namespace mdb
#pragma once
#include <common.h>

namespace utils {

template <typename C>
constexpr auto
copy_to(C &c, C &out)
{
  std::copy(c.begin(), c.end(), std::back_inserter(out));
}

template <typename C, typename Fn>
constexpr auto
copy_to_transform(C &c, C &out, Fn transform)
{
  std::transform(c.begin(), c.end(), std::back_inserter(out), transform);
}

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
      : interval({IntervalNode<MapDatum, A>{.addr = std::numeric_limits<A>::min(), .values = {}},
                  IntervalNode<MapDatum, A>{.addr = std::numeric_limits<A>::max(), .values = {}}})
  {
  }

  /**
   * Add the mapping [ `start` .. `end` ] -> `value`, such that any search with keys that range between these two
   * endpoints (inclusively), will return `value`, as well as any other `value` whose range-mapping intersects with
   * the key.
   */
  void
  add_mapping(A start, A end, MapDatum value)
  {
    auto it_a = maybe_partition_at<EndpointType::Start>(find_index_of<false>(start), start);
    auto it_b = maybe_partition_at<EndpointType::End>(find_index_of<false>(end), end);

    for (; it_a < it_b; ++it_a) {
      it_a->values.push_back({false, value});
    }
    it_a->values.push_back({true, value});
  }

  /**
   * Find what values have a range that covers `key`. Returns found values. If nothing was found return `None`.
   */
  std::optional<std::vector<MapDatum>>
  find(A key) const
  {
    auto pos = find_index_of<true>(key);
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
  find(A key, std::vector<MapDatum> &write_to_result) noexcept
  {
    auto pos = find_index_of<true>(key);
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
  node_addr_equals(size_t index, A addr) noexcept
  {
    return interval[index].addr == addr;
  }

  constexpr auto
  find_index_to_insert_at(A pc) const noexcept
  {
    constexpr auto find = [](const IntervalNode<MapDatum, A> &node, auto pc) { return node.addr < pc; };

    auto it = std::lower_bound(interval.begin(), interval.end(), pc, find);
    auto dist = std::distance(interval.begin(), it);
    return dist;
  }

  template <bool AlsoEquals>
  constexpr auto
  find_index_of(A pc) const noexcept
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
  ensure_no_iterator_invalidation() noexcept
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
  maybe_partition_at(size_t index, A with_addr) noexcept
  {
    if constexpr (type == EndpointType::Start) {
      ensure_no_iterator_invalidation();
    }

    // a node with this address already exists, no need to partition the range
    // [N .. M] that contains `with_addr`
    if (node_addr_equals(index, with_addr)) {
      return interval.begin() + index;
    }

    if constexpr (type == EndpointType::Start) {
      auto it =
        interval.insert(interval.begin() + index, IntervalNode<MapDatum, A>{.addr = with_addr, .values = {}});
      copy_to(interval[index - 1].values, it->values);
    } else {
      auto it =
        interval.insert(interval.begin() + index, IntervalNode<MapDatum, A>{.addr = with_addr, .values = {}});
      if (index < interval.size() - 1) {
        copy_to_transform(interval[index + 1].values, it->values, [](auto it) {
          auto copy = it;
          copy.end = false;
          return copy;
        });
      }
    }
    return interval.begin() + index;
  }
};

} // namespace utils
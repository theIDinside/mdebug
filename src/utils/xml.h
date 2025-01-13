/** LICENSE TEMPLATE */
#pragma once
#include "utils/immutable.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace xml {
// Forward declarations
struct XMLElementView;
using ElementList = std::vector<Immutable<XMLElementView>>;

class RefMap
{
  std::unordered_map<std::string_view, std::string_view> storage{};

public:
  void insert(std::string_view attr, std::string_view value) noexcept;
  std::optional<std::string_view> attribute(std::string_view name) const noexcept;

  auto
  begin() const noexcept
  {
    return std::begin(storage);
  }

  auto
  end() const noexcept
  {
    return std::end(storage);
  }
};

// TODO(simon): Change this to std::vector<pair<str, str>> instead
using AttributeMapView = RefMap;

// An element that contains data that is (possibly) is a temporary reference
struct XMLElementView
{
  std::string_view name;
  AttributeMapView attributes;
  ElementList children;
  std::string_view content;

  constexpr std::optional<std::string_view>
  attribute(std::string_view name) const noexcept
  {
    return attributes.attribute(name);
  }
};

struct XMLDocument
{
  std::vector<XMLElementView> top_elements{};
};

class XMLParser
{
  std::string_view input;
  std::string_view pbuf;

public:
  XMLParser(std::string_view data) noexcept;
  Immutable<XMLElementView> parse() noexcept;

private:
  Immutable<XMLElementView> parse_element() noexcept;
  std::string_view parse_name() noexcept;
  AttributeMapView parse_attributes() noexcept;
  std::string_view parse_attr_value() noexcept;
  char eat_char() noexcept;
  std::string_view take_n(size_t count) noexcept;
  void eat_n(size_t count) noexcept;
  void skip_whitespace() noexcept;
  void parse_close_tag() noexcept;
};

std::vector<const XMLElementView *> collect_by_name(const XMLElementView &root, std::string_view name,
                                                    bool can_contain_children, u32 guess_total = 85) noexcept;

} // namespace xml
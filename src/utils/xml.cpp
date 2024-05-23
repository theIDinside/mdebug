#include "xml.h"
#include "common.h"
#include "utils/util.h"
#include <algorithm>
#include <bits/ranges_algo.h>
#include <bits/ranges_util.h>
#include <cctype>

namespace xml {

void
RefMap::insert(std::string_view attr, std::string_view value) noexcept
{
  storage.emplace(attr, value);
}

std::optional<std::string_view>
RefMap::attribute(std::string_view name) const noexcept
{
  if (auto it = storage.find(name); it != std::cend(storage)) {
    return it->second;
  }
  return std::nullopt;
}

XMLParser::XMLParser(std::string_view data) noexcept : input(data), pbuf(data) {}

Immutable<XMLElementView>
XMLParser::parse() noexcept
{
  XMLElementView root;
  while (pbuf.size() > 2) {
    // look for < but not </ since it's just a closing tag. We eat those.
    const auto next = pbuf[1];
    if (pbuf.front() == '<' && next != '/') {
      // we ignore comments and <?element?>s
      if (next == '?' || next == '!') {
        for (auto i = 2u; i < pbuf.size(); ++i) {
          if (pbuf[i] == '>') {
            pbuf.remove_prefix(i + 1);
            break;
          }
        }
      } else {
        pbuf.remove_prefix(1);
        return parse_element();
      }
    } else {
      pbuf.remove_prefix(1);
    }
  }
  return root;
}

void
XMLParser::parse_close_tag() noexcept
{
  pbuf.remove_prefix(2);
  parse_name(); // consume the element name
  pbuf.remove_prefix(1);
}

Immutable<XMLElementView>
XMLParser::parse_element() noexcept
{
  XMLElementView element;

  // Parse the element name
  element.name = parse_name();

  // Parse attributes
  element.attributes = parse_attributes();

  // Handle self-closing tag
  if (pbuf.front() == '/') {
    eat_n(2);
    return element;
  }

  // Consume the closing '>'
  const auto closing_bracket = eat_char();
  ASSERT(closing_bracket == '>', "Expected a closing '>'");

  // Parse content or child elements
  auto start = pbuf.front() != '<' ? pbuf.data() : nullptr;
  while (pbuf.size() > 2) {
    if (pbuf.front() == '<') {
      if (start) {
        element.content = std::string_view{start, pbuf.data()};
        if (std::ranges::all_of(element.content, [](auto ch) { return isspace(ch); })) {
          element.content = {};
        }
        start = nullptr;
      }
      if (pbuf[1] == '/') {
        parse_close_tag();
        break;
      } else {
        pbuf.remove_prefix(1);
        element.children.push_back(parse_element());
      }
    } else {
      eat_char();
    }
  }

  return element;
}

std::string_view
XMLParser::parse_name() noexcept
{
  std::string name;
  auto it = std::ranges::find_if(pbuf, [](const auto ch) { return !(isalnum(ch) || ch == '-' || ch == ':'); });
  const auto result = std::string_view{pbuf.begin(), it};
  pbuf.remove_prefix(result.size());
  return result;
}

AttributeMapView
XMLParser::parse_attributes() noexcept
{
  AttributeMapView attributes;
  while (true) {
    skip_whitespace();
    if (char c = pbuf.front(); c == '/' || c == '>') {
      break;
    }
    const auto name = parse_name();

    skip_whitespace();
    const auto eq_sign = eat_char();
    ASSERT(eq_sign == '=', "Expected an equals sign");
    skip_whitespace();
    std::string_view value = parse_attr_value();
    attributes.insert(name, value);
  }
  return attributes;
}

std::string_view
XMLParser::parse_attr_value() noexcept
{
  const char quote = eat_char();
  ASSERT(quote == '"', "Expected quote but saw {}", quote);
  auto pos = pbuf.find('"');
  if (pos == std::string_view::npos) {
    const auto res = pbuf;
    pbuf.remove_prefix(pbuf.size());
    return res;
  }
  const std::string_view res{pbuf.begin(), pos};
  pbuf.remove_prefix(std::min(pos + 1, pbuf.size()));

  return res;
}

char
XMLParser::eat_char() noexcept
{
  char c = pbuf.front();
  pbuf.remove_prefix(1);
  return c;
}

std::string_view
XMLParser::take_n(size_t count) noexcept
{
  if (count == std::string_view::npos) {
    const auto copy = pbuf;
    pbuf.remove_prefix(pbuf.size());
    return copy;
  }
  const std::string_view res{pbuf.begin(), pbuf.begin() + count};
  pbuf.remove_prefix(count);
  return res;
}

void
XMLParser::eat_n(size_t count) noexcept
{
  pbuf.remove_prefix(std::min(count, pbuf.size()));
}

void
XMLParser::skip_whitespace() noexcept
{
  pbuf.remove_prefix(utils::position(pbuf, [](char c) { return !isspace(c); }).value_or(0));
}

static void
collect_by_name_impl(std::vector<const XMLElementView *> &cache, const XMLElementView &root, std::string_view name,
                     bool can_contain_children) noexcept
{
  if (root.name == name) {
    cache.push_back(&root);
    if (can_contain_children) {
      for (const auto &child : root.children) {
        collect_by_name_impl(cache, child, name, can_contain_children);
      }
    }
  } else {
    for (const auto &child : root.children) {
      collect_by_name_impl(cache, child, name, can_contain_children);
    }
  }
}

std::vector<const XMLElementView *>
collect_by_name(const XMLElementView &root, std::string_view name, bool can_contain_children,
                u32 guess_total) noexcept
{
  std::vector<const XMLElementView *> result{};
  result.reserve(guess_total);
  collect_by_name_impl(result, root, name, can_contain_children);
  return result;
}

} // namespace xml
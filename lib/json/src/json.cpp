/** LICENSE TEMPLATE */
#include <charconv>
#include <json/json.h>

// system headers
#include <expected>
#include <format>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>

#include <span>

using namespace std::string_view_literals;

namespace mdbjson {

bool
JsonValue::IsBoolean() const noexcept
{
  return mType == Type::Boolean;
}

bool
JsonValue::IsString() const noexcept
{
  return mType == Type::String;
}

bool
JsonValue::IsNumber() const noexcept
{
  return mType == Type::Number;
}

bool
JsonValue::IsArray() const noexcept
{
  return mType == Type::Array;
}

bool
JsonValue::IsObject() const noexcept
{
  return mType == Type::Object;
}

bool
JsonValue::IsNull() const noexcept
{
  return mType == Type::Null;
}

const BooleanType *
JsonValue::UncheckedGetBoolean() const noexcept
{
  return &mData.boolean;
}

const StringType *
JsonValue::UncheckedGetString() const noexcept
{
  return mData.string;
}

std::string_view
JsonValue::UncheckedGetStringView() const noexcept
{
  return std::string_view{ *mData.string };
}

const double *
JsonValue::UncheckedGetNumber() const noexcept
{
  return &mData.number;
}

const ArrayType *
JsonValue::UncheckedGetArray() const noexcept
{
  return mData.array;
}

const JsonValue *
JsonValue::UncheckedGetProperty(std::string_view property) const noexcept
{
  const auto &object = *mData.object;
  auto it = object.find(property);
  // TODO: Possibly benchmark this. The idea is this though
  // for _our_ very niche use of json, we will be doing GetProperty on things we _expect_ to be there. If they're
  // not, we're ok with paying any potential overhead/penalty for missing our assumption.
  if (it != std::end(object)) [[likely]] {
    return &it->second;
  }
  return nullptr;
}

std::span<const JsonValue>
JsonValue::AsSpan() const noexcept
{
  if (!IsArray()) {
    return std::span<const JsonValue>{};
  }

  return std::span{ *mData.array };
}

std::span<const JsonValue>
JsonValue::AsSpan(std::string_view property) const noexcept
{
  if (!IsObject()) {
    return {};
  }

  const auto *prop = UncheckedGetProperty(property);
  return prop ? prop->AsSpan() : std::span<const JsonValue>{};
}

const BooleanType *
JsonValue::GetBoolean() const noexcept
{
  if (mType != Type::Boolean) [[unlikely]] {
    return nullptr;
  }

  return UncheckedGetBoolean();
}

const StringType *
JsonValue::GetString() const noexcept
{
  if (mType != Type::String) {
    return nullptr;
  }

  return UncheckedGetString();
}

std::optional<std::string_view>
JsonValue::GetStringView() const noexcept
{
  const auto *str = GetString();
  if (!str) {
    return {};
  }
  return std::string_view{ *str };
}

const double *
JsonValue::GetNumber() const noexcept
{
  if (mType != Type::Number) {
    return nullptr;
  }
  return UncheckedGetNumber();
}

const ArrayType *
JsonValue::GetArray() const noexcept
{
  if (mType != Type::Array) {
    return nullptr;
  }
  return UncheckedGetArray();
}

const JsonValue *
JsonValue::At(std::string_view property) const noexcept
{
  if (!IsObject()) [[unlikely]] {
    return nullptr;
  }

  return UncheckedGetProperty(property);
}

std::optional<const JsonValue>
JsonValue::Get(std::string_view property) const noexcept
{
  if (!IsObject()) [[unlikely]] {
    return {};
  }

  if (auto prop = UncheckedGetProperty(property); prop) {
    return *prop;
  }
  return {};
}

bool
JsonValue::Contains(std::string_view property) const noexcept
{
  return IsObject() ? mData.object->contains(property) : false;
}

static bool
Lex(std::string_view input, std::pmr::vector<Token> &outBuffer, ParseError &error) noexcept
{
  return true;
}

#define PARSE_ERROR_RETURN(Error, Position)                                                                       \
  error = ParseError{ ParseError::ErrorKind::Error, i64(Position) };                                              \
  return false;

#define PROPAGATE_RESULT(res) return res;
class Parser
{
public:
  Parser(std::pmr::memory_resource *arena, std::string_view input) noexcept : mArena(arena), mInput(mArena)
  {
    mInput.reserve(input.size());
    // The serialized JSON data is copied into the allocator's memory blocks, and will now live as long as the JSON
    // that gets parsed from it.
    std::copy(input.begin(), input.end(), std::back_inserter(mInput));
  }

  constexpr std::expected<JsonValue, ParseError>
  Parse() noexcept
  {
    JsonValue value;
    ParseError error;

    if (ParseValue(&value, error)) [[likely]] {
      return value;
    }

    return std::unexpected(error);
  }

private:
  std::pmr::memory_resource *mArena;
  std::pmr::string mInput;
  size_t mPos{ 0 };

  constexpr bool
  CanReadMore() const noexcept
  {
    return mPos < mInput.size();
  }

  bool
  ParseValue(JsonValue *value, ParseError &error)
  {
    SkipWhitespace();
    if (!CanReadMore()) {
      PARSE_ERROR_RETURN(UnexpectedEndOfInput, mPos);
    }

    const char head = mInput[mPos];

    switch (head) {
    case 'n':
      return ParseNull(value, error);
    case 't':
      [[fallthrough]];
    case 'f':
      return ParseBoolean(value, error);
    case '-':
      [[fallthrough]];
    case '0' ... '9':
      return ParseNumber(value, error);
    case '"':
      return ParseString(value, error);
    case '[':
      return ParseArray(value, error);
    case '{':
      return ParseObject(value, error);
    default:
      PARSE_ERROR_RETURN(UnexpectedCharacter, mPos);
    }
  }

  void
  SkipWhitespace()
  {
    while (CanReadMore() && std::isspace(mInput[mPos])) {
      ++mPos;
    }
  }

  constexpr bool
  ParseNull(JsonValue *value, ParseError &error) noexcept
  {
    if (mInput.substr(mPos, 4) != "null"sv) {
      PARSE_ERROR_RETURN(InvalidToken, mPos);
    }
    mPos += 4;
    value->mType = Type::Null;
    value->mData.null = nullptr;
    return true;
  }

  constexpr bool
  ParseBoolean(JsonValue *value, ParseError &error) noexcept
  {
    // MAYBE_TODO(simon) can we use SWAR here? (true / false is just 4 or 5 bytes, so using SIMD here is not giving
    // us anything. probably even slower)
    if (mInput.substr(mPos, 4) == "true"sv) {
      mPos += 4;
      value->mType = Type::Boolean;
      value->mData.boolean = true;
      return true;
    } else if (mInput.substr(mPos, 5) == "false"sv) {
      mPos += 5;
      value->mType = Type::Boolean;
      value->mData.boolean = false;
      return true;
    }
    PARSE_ERROR_RETURN(InvalidToken, mPos);
  }

  // Create a (absolutely) compile time lookup table/array
  static consteval std::array<bool, std::numeric_limits<char>::max()>
  ValidCharactersArray() noexcept
  {
    std::array<bool, std::numeric_limits<char>::max()> lookupTable{};
    for (auto &v : lookupTable) {
      v = false;
    }

    for (const auto ch : { '-', '+', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', 'e', 'E' }) {
      lookupTable[static_cast<u8>(ch)] = true;
    }
    return lookupTable;
  }

  constexpr bool
  ParseNumber(JsonValue *value, ParseError &error) noexcept
  {
    size_t start = mPos;

    constexpr auto isJsonNumberChar = [](const char ch) noexcept {
      static constexpr auto lookupTable = ValidCharactersArray();
      return lookupTable[ch];
    };

    while (CanReadMore() && isJsonNumberChar(mInput[mPos])) {
      ++mPos;
    }

    double number;
    // TODO: from_chars I'm expecting to be half decent actually. But perhaps this is not the case.
    auto [ptr, ec] = std::from_chars(mInput.data() + start, mInput.data() + mPos, number);
    if (ec != std::errc()) {
      PARSE_ERROR_RETURN(InvalidNumber, start);
    }

    value->mType = Type::Number;
    value->mData.number = number;
    return true;
  }

  constexpr bool
  ParseString(JsonValue *value, ParseError &error) noexcept
  {
    if (mInput[mPos] != '"') {
      PARSE_ERROR_RETURN(ExpectedValue, mPos);
    }
    ++mPos;
    value->mType = Type::String;
    std::pmr::string *myStr = Allocate<std::pmr::string>(1);

    value->mData.string = myStr;
    std::pmr::string &str = *value->mData.string;

    // TODO: When two-phase parse has been written, pre-allocate the size of the entire string
    // and copy it. Escaping must happen regardless though. but a Token { Type::String, start, end, mChildCount }
    // can tuck away the unescaped character/byte count into it's "child cound" value, like how Array and
    // Object tokens will do.

    while (CanReadMore()) {
      const char c = mInput[mPos++];
      if (c == '"') {
        break;
      }
      if (c == '\\') {
        if (!CanReadMore()) {
          PARSE_ERROR_RETURN(InvalidStringEscape, mPos);
        }
        char esc = mInput[mPos++];
        switch (esc) {
        case '"':
          str.push_back('"');
          break;
        case '\\':
          str.push_back('\\');
          break;
        case '/':
          str.push_back('/');
          break;
        case 'b':
          str.push_back('\b');
          break;
        case 'f':
          str.push_back('\f');
          break;
        case 'n':
          str.push_back('\n');
          break;
        case 'r':
          str.push_back('\r');
          break;
        case 't':
          str.push_back('\t');
          break;
        default:
          PARSE_ERROR_RETURN(InvalidStringEscape, mPos);
        }
      } else {
        str.push_back(c);
      }
    }

    return true;
  }

  constexpr bool
  ParseArray(JsonValue *value, ParseError &error) noexcept
  {
    if (mInput[mPos] != '[') {
      PARSE_ERROR_RETURN(ExpectedValue, mPos);
    }
    ++mPos;

    auto *arr = Allocate<std::pmr::vector<JsonValue>>(1);

    SkipWhitespace();
    if (CanReadMore() && mInput[mPos] == ']') {
      ++mPos;
      value->mType = Type::Array;
      value->mData.array = arr;
      return true;
    }

    while (true) {
      JsonValue &arrayValue = arr->emplace_back(JsonValue{});
      if (!ParseValue(&arrayValue, error)) {
        return false;
      }

      SkipWhitespace();
      if (!CanReadMore()) {
        PARSE_ERROR_RETURN(UnexpectedEndOfInput, mPos);
      }
      if (mInput[mPos] == ',') {
        ++mPos;
        SkipWhitespace();
        continue;
      }
      if (mInput[mPos] == ']') {
        ++mPos;
        break;
      }
      PARSE_ERROR_RETURN(ExpectedCommaOrEnd, mPos);
    }

    value->mType = Type::Array;
    value->mData.array = arr;
    return true;
  }

  constexpr std::optional<std::string_view>
  ParseKeyString(ParseError &error) noexcept
  {
    if (mInput[mPos] != '"') {
      error = ParseError{ ParseError::ErrorKind::UnexpectedCharacter, i64(mPos) };
      return {};
    }
    ++mPos;
    auto keyStart = mPos;
    while (CanReadMore() && mInput[mPos] != '"') {
      ++mPos;
      if (mInput[mPos] == '\\') [[unlikely]] {
        ++mPos;
        ++mPos;
      }
    }

    if (!CanReadMore()) {
      error = ParseError{ ParseError::ErrorKind::UnexpectedEndOfInput, i64(mPos) };
    }

    const auto keyLength = mPos - keyStart;
    // move past the '"'
    ++mPos;

    return std::string_view{ mInput }.substr(keyStart, keyLength);
  }

  constexpr bool
  ParseObject(JsonValue *value, ParseError &error) noexcept
  {
    if (mInput[mPos] != '{') {
      PARSE_ERROR_RETURN(ExpectedValue, mPos);
    }
    ++mPos;

    // Create a polymorphic allocator for strings
    ObjectType *obj = Allocate<ObjectType>(1);

    SkipWhitespace();
    if (CanReadMore() && mInput[mPos] == '}') {
      ++mPos;
      value->mType = Type::Object;
      value->mData.object = obj;
      return true;
    }

    while (true) {
      SkipWhitespace();
      auto keyVal = ParseKeyString(error);
      if (!keyVal.has_value()) {
        return false;
      }

      SkipWhitespace();
      if (!CanReadMore() || mInput[mPos] != ':') {
        PARSE_ERROR_RETURN(ExpectedColon, mPos);
      }
      ++mPos;

      auto result = obj->emplace(*keyVal, JsonValue{});
      auto &[it, success] = result;

      if (!ParseValue(&it->second, error)) {
        return false;
      }

      SkipWhitespace();
      if (!CanReadMore()) {
        PARSE_ERROR_RETURN(UnexpectedEndOfInput, mPos);
      }
      if (mInput[mPos] == ',') {
        ++mPos;
        continue;
      }
      if (mInput[mPos] == '}') {
        ++mPos;
        break;
      }
      PARSE_ERROR_RETURN(ExpectedCommaOrEnd, mPos);
    }

    value->mType = Type::Object;
    value->mData.object = obj;
    return true;
  }

  template <typename T, typename... Args>
  constexpr T *
  Allocate(size_t count, Args &&...args)
  {
    if constexpr (std::is_same_v<T, JsonValue>) {
      void *mem = mArena->allocate(sizeof(T), alignof(T));
      return new (mem) T(std::forward<Args>(args)...);
    } else {
      std::pmr::polymorphic_allocator<T> allocator(mArena);
      T *obj = allocator.template allocate_object<T>(count);
      return std::construct_at(obj, std::forward<Args>(args)..., std::pmr::polymorphic_allocator<T>(mArena));
    }
  }
};

consteval auto
LengthOfError(ParseError::ErrorKind kind)
{
#define CASE_OF(Kind)                                                                                             \
  case ParseError::ErrorKind::Kind:                                                                               \
    return std::string_view{ #Kind }.size();
  switch (kind) {
    FOR_EACH_PARSE_ERROR(CASE_OF)
  }
#undef CASE_OF

  return std::string_view{ "Could not determine error" }.size();
}

#define ERROR_CASE(Kind)                                                                                          \
  case ErrorKind::Kind: {                                                                                         \
    std::pmr::string r{ memoryResource };                                                                         \
    r.reserve(LengthOfError(ErrorKind::Kind) + 1 + len);                                                          \
    std::format_to(std::back_inserter(r), #Kind " {}", pos);                                                      \
  }

/** static */
std::pmr::string
ParseError::ToString(std::pmr::memory_resource *memoryResource, ParseError error) noexcept
{
  static constexpr auto BaseTenDigitsFor64BitValue = 20;
  static constexpr auto PositionFormatString = "Position {{ {} }}"sv;
  char posBuf[PositionFormatString.size() + BaseTenDigitsFor64BitValue];
  auto it = std::format_to(posBuf, PositionFormatString, error.mPosition);
  const auto len = std::distance(posBuf, it);
  std::string_view pos{ posBuf, it };

  switch (error.mKind) {
    FOR_EACH_PARSE_ERROR(ERROR_CASE)
  }

  return "";
}

std::expected<JsonValue, ParseError>
Parse(std::pmr::memory_resource *jsonAllocator, std::string_view input) noexcept
{
  // TODO(simon): Introduce a two-phase parse. We do in-line allocations which means we're reallocating some times
  // when it comes to array elements or string buffers. That's not amazing. By introducing a two-phase parse we can
  // first lex then also store the metadata of how many elements things contain and allocate exactly, ahead of time
  // in phase-2 of parsing.
  Parser parser(jsonAllocator, input);
  return parser.Parse();
}

} // namespace mdbjson
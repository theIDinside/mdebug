/** LICENSE TEMPLATE */
#include <charconv>
#include <json/json.h>

// system headers
#include <expected>
#include <format>
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
JsonValue::GetProperty(std::string_view property) const noexcept
{
  if (!IsObject()) [[unlikely]] {
    return nullptr;
  }

  return UncheckedGetProperty(property);
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
  Parser(std::pmr::memory_resource *arena, std::string_view input) noexcept : mArena(arena), mInput(input) {}

  constexpr std::expected<JsonValue *, ParseError>
  Parse() noexcept
  {
    JsonValue *value = Allocate<JsonValue>();
    ParseError error;

    if (ParseValue(value, error)) [[likely]] {
      return value;
    }

    return std::unexpected(error);
  }

private:
  std::pmr::memory_resource *mArena;
  std::string_view mInput;
  size_t mPos{ 0 };

  bool
  ParseValue(JsonValue *value, ParseError &error)
  {
    SkipWhitespace();
    if (mPos >= mInput.size()) {
      PARSE_ERROR_RETURN(UnexpectedEndOfInput, mPos);
    }

    const char head = mInput[mPos];

    switch (head) {
    case 'n':
      PROPAGATE_RESULT(ParseNull(value, error));
    case 't':
      [[fallthrough]];
    case 'f':
      PROPAGATE_RESULT(ParseBoolean(value, error));
    case '-':
      [[fallthrough]];
    case '0' ... '9':
      PROPAGATE_RESULT(ParseNumber(value, error));
    case '"':
      PROPAGATE_RESULT(ParseString(value, error));
    case '[':
      PROPAGATE_RESULT(ParseArray(value, error));
    case '{':
      PROPAGATE_RESULT(ParseObject(value, error));
    default:
      PARSE_ERROR_RETURN(UnexpectedCharacter, mPos);
    }
  }

  void
  SkipWhitespace()
  {
    while (mPos < mInput.size() &&
           (mInput[mPos] == ' ' || mInput[mPos] == '\t' || mInput[mPos] == '\n' || mInput[mPos] == '\r')) {
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

  constexpr bool
  ParseNumber(JsonValue *value, ParseError &error) noexcept
  {
    size_t start = mPos;
    if (mInput[mPos] == '-') {
      ++mPos;
    }
    if (mPos >= mInput.size()) {
      PARSE_ERROR_RETURN(InvalidNumber, mPos);
    }
    if (mInput[mPos] == '0') {
      ++mPos;
    } else if (mInput[mPos] >= '1' && mInput[mPos] <= '9') {
      while (mPos < mInput.size() && mInput[mPos] >= '0' && mInput[mPos] <= '9') {
        ++mPos;
      }
    } else {
      PARSE_ERROR_RETURN(InvalidNumber, mPos);
    }
    if (mPos < mInput.size() && mInput[mPos] == '.') {
      ++mPos;
      if (mPos >= mInput.size() || !(mInput[mPos] >= '0' && mInput[mPos] <= '9')) {
        PARSE_ERROR_RETURN(InvalidNumber, mPos);
      }
      while (mPos < mInput.size() && mInput[mPos] >= '0' && mInput[mPos] <= '9') {
        ++mPos;
      }
    }
    if (mPos < mInput.size() && (mInput[mPos] == 'e' || mInput[mPos] == 'E')) {
      ++mPos;
      if (mPos < mInput.size() && (mInput[mPos] == '+' || mInput[mPos] == '-')) {
        ++mPos;
      }
      if (mPos >= mInput.size() || !(mInput[mPos] >= '0' && mInput[mPos] <= '9')) {
        PARSE_ERROR_RETURN(InvalidNumber, mPos);
      }
      while (mPos < mInput.size() && mInput[mPos] >= '0' && mInput[mPos] <= '9') {
        ++mPos;
      }
    }

    double number;
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
    // Create a polymorphic allocator for strings
    std::pmr::polymorphic_allocator<std::pmr::string> obj_alloc(mArena);

    // Allocate the string itself using the allocator
    std::pmr::string *myStr = obj_alloc.allocate_object<std::pmr::string>(1);

    value->mData.string = myStr;
    std::pmr::string &str = *value->mData.string;

    while (mPos < mInput.size()) {
      char c = mInput[mPos++];
      if (c == '"') {
        break;
      }
      if (c == '\\') {
        if (mPos >= mInput.size()) {
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

    // Create a polymorphic allocator for strings
    std::pmr::polymorphic_allocator<std::pmr::vector<JsonValue>> obj_alloc(mArena);

    // Allocate the string itself using the allocator
    auto *arr = obj_alloc.allocate_object<std::pmr::vector<JsonValue>>(1);

    SkipWhitespace();
    if (mPos < mInput.size() && mInput[mPos] == ']') {
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
      if (mPos >= mInput.size()) {
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
    while (mPos < mInput.size() && mInput[mPos] != '"') {
      ++mPos;
      if (mInput[mPos] == '\\') [[unlikely]] {
        ++mPos;
        ++mPos;
      }
    }

    if (mPos >= mInput.size()) {
      error = ParseError{ ParseError::ErrorKind::UnexpectedEndOfInput, i64(mPos) };
    }

    const auto keyLength = mPos - keyStart;
    // move past the '"'
    ++mPos;

    return mInput.substr(keyStart, keyLength);
  }

  constexpr bool
  ParseObject(JsonValue *value, ParseError &error) noexcept
  {
    if (mInput[mPos] != '{') {
      PARSE_ERROR_RETURN(ExpectedValue, mPos);
    }
    ++mPos;

    // Create a polymorphic allocator for strings
    std::pmr::polymorphic_allocator<ObjectType> obj_alloc(mArena);

    // Allocate the string itself using the allocator
    ObjectType *obj = obj_alloc.allocate_object<ObjectType>(1);

    SkipWhitespace();
    if (mPos < mInput.size() && mInput[mPos] == '}') {
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
      if (mPos >= mInput.size() || mInput[mPos] != ':') {
        PARSE_ERROR_RETURN(ExpectedColon, mPos);
      }
      ++mPos;

      auto result = obj->emplace(*keyVal, JsonValue{});
      auto &[it, success] = result;

      if (!ParseValue(&it->second, error)) {
        return false;
      }

      SkipWhitespace();
      if (mPos >= mInput.size()) {
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
  Allocate(Args &&...args)
  {
    if constexpr (std::is_same_v<T, JsonValue>) {
      void *mem = mArena->allocate(sizeof(T), alignof(T));
      return new (mem) T(std::forward<Args>(args)...);
    } else {
      void *mem = mArena->allocate(sizeof(T), alignof(T));
      return new (mem) T(std::forward<Args>(args)..., mArena);
    }
  }
};

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
  char posBuf[64];
  auto it = std::format_to(posBuf, "Position {{ {} }}", error.mPosition);
  const auto len = std::distance(posBuf, it);
  std::string_view pos{ posBuf, it };

  switch (error.mKind) {
    FOR_EACH_PARSE_ERROR(ERROR_CASE)
  }

  return "";
}

std::expected<JsonValue *, ParseError>
Parse(std::pmr::memory_resource *jsonAllocator, std::string_view input)
{
  Parser parser(jsonAllocator, input);
  return parser.Parse();
}

} // namespace mdbjson
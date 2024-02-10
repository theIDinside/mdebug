struct FloatStringDoubleIntPair
{
  float f;
  const char *n;
  double d;
  int a, b;
};

struct FloatStringDoubleIntArr
{
  float f;
  const char *n;
  double d;
  int a[4];
};

// type > 16 bytes: should be returned via implicit pointer (passed in as %rdi, on %rax in return)
FloatStringDoubleIntPair
createFloatStringDoubleIntPair(int a, int b, const char *name)
{
  return FloatStringDoubleIntPair{.f = 0.125, .n = name, .d = 0.997, .a = a, .b = b};
}

// type > 16 bytes: should be returned via implicit pointer (passed in as %rdi, on %rax in return)
FloatStringDoubleIntArr
createFloatStringDoubleIntArr(float f, double d, const char *name, int arrayValues)
{
  return FloatStringDoubleIntArr{
      .f = f, .n = name, .d = d, .a = {arrayValues, arrayValues, arrayValues, arrayValues}};
}

struct FloatString
{
  float f;
  const char *str;
};

// type <= 16 bytes: since struct contains float, float will be in %xmmN, const char* in %rax
FloatString
createFloatString(const char *name)
{
  return FloatString{.f = 0.125, .str = name};
}

// type <= 16 bytes: struct contains floating point value (double), float will be in %xmmN, const char* in %rax
struct DoubleString
{
  double f;
  const char *str;
};

// type <= 16 bytes: struct contains floating point values, returned in %xmmN
struct TwoDoubles
{
  double a;
  double b;
};

// type >= 16 bytes: Should automatically be implicit pointer via ->%rdi, ->%rax.
// but since the two doubles actually fit in a %xmm, and const char* fits in %rax, I wonder if that still is true.
struct TwoAndAPointer
{
  TwoDoubles doubles;
  const char *n;
};

TwoDoubles
createTwoDoubles(double a)
{
  return TwoDoubles{a * 2, a * 5};
}

TwoAndAPointer
createTwo(double a, const char *name)
{
  return TwoAndAPointer{.doubles = {a * 2, a * 5}, .n = name};
}

DoubleString
createDoubleString(const char *name)
{
  return DoubleString{.f = 0.125, .str = name};
}

struct BigStruct
{
  int integerArray[8];
  const char *bigName;
  const char *smallName;
};

void
run_functions_where_we_can_determine_return_value_convention()
{
  auto dblString = createDoubleString("A double with a string pointer");
  auto fltString = createFloatString("A float with a string pointer");
  auto fltStrDoubleIntArr = createFloatStringDoubleIntArr(
      0.125, 0.997, "A float, double, string pointer and array of 4 ints of value 42", 42);
  auto fltStrDblIntPair =
      createFloatStringDoubleIntPair(1, 2, "Createa  float, string pointer, double and two ints");
  auto twoDoubles = createTwoDoubles(0.1337);
  auto twoAndAPointer = createTwo(
      0.1337, "Is this returned via implicit rdi then out via rax, or some constellation of xmm and rax?");
}

struct Structure
{
  const char *name;
  int count;
  float fraction;
};

class Class
{
  int classInt;
  Structure classInfo;

public:
  Class(int constructorInt, Structure info) : classInt(constructorInt), classInfo(info)
  {
    int a = 42; // CLASS_BP
  }

  Structure
  getClassInfo()
  {
    auto modifiedInfo = classInfo;
    modifiedInfo.count += classInt;
    return modifiedInfo;
  }
};

void
structured_byvalue(Structure s)
{
  int add = 10;
  auto clone = s;
  clone.count += add; // BYVAL_BP
}

void
structured_ref(Structure &s)
{
}

void
structured_ptrref(Structure *s)
{
}

void
structured(const char *name, int count, float fr)
{
  Structure structure{name, count, fr};
  structure.count += 1;
  structure.fraction += 0.02; // STRUCT_BP
  structured_byvalue(structure);
  structured_ref(structure);
  structured_ptrref(&structure);
}

void
locals()
{
  int a = 10;
  int b = 20;
  int c = 30;
  double d = 239.234;
  const char *str = "Hello world!";
  auto res = a + b + c; // LOC_BP
}

void
args(int a, float b, long c)
{
  int res_a = a * 2;
  float res_b = b * 4.0;
  long res_c = c * 8; // ARGS_BP
}

Structure
createStruct(const char *name, int i, float frac)
{
  return Structure{name, i, frac};
}

BigStruct
createBig(const char *smallName, const char *bigName)
{
  auto res = BigStruct{
      .integerArray = {},
      .bigName = bigName,
      .smallName = smallName,
  };
  auto cnt = 0;
  auto it = smallName;
  while (it != nullptr && *it != 0) {
    cnt++;
    ++it;
  }

  for (auto i = 0; i < 8; ++i) {
    res.integerArray[i] += cnt + i;
  }
  return res;
}

void
lexical_block(const char *name, bool should_take)
{
  int a = 0;
  Structure structure = createStruct(name, 1, 1.25);
  if (should_take) {
    a = 1;
    float b = 3.14;
    args(a, b, 1337); // LEX_BLOCK
    Class myClass{a, structure};
    const auto newStructure = myClass.getClassInfo();
    const auto big = createBig("Args", "Locals");
  } else {
    locals();
  }
  {
    int lastInt = 42;
  }
  int anotherMofo = 1337;
}

int
main(int argc, const char **argv)
{
  lexical_block("Args", true);
  lexical_block("Locals", false);
  structured("foo", 42, 0.39);
  run_functions_where_we_can_determine_return_value_convention();
}
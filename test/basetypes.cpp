
struct Structure
{
  const char *name;
  int count;
  float fraction;
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

void
lexical_block(const char *name, bool should_take)
{
  int a = 0;
  Structure structure{name, 1, 1.25};
  if (should_take) {
    a = 1;
    float b = 3.14;
    long c = 1337;
    args(a, b, c); // LEX_BLOCK
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
}
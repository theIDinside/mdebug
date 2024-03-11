#include "dynamic_lib.h"
#include "templated_code/template.h"
// Comments are source-code identifiers for setting breakpoints from the driver tests. Do not remove.

float
min_float(float a, float b)
{
  return less_than(a, b);
}

float
convert_celsius_to_fahrenheit(float celsius)
{
  return ((celsius * 9) / 5.0) + 32; // BPCE
}

float
convert_fahrenheit_to_celsius(float fahrenheit)
{
  return ((fahrenheit - 32) * 5) / 9.0; // BPFA
}

float
convert_kilometers_to_miles(float kilometers)
{
  return kilometers / 1.619344; // BPKM
}

float
convert_miles_to_kilometers(float miles)
{
  return miles * 1.619344; // BPMI
}
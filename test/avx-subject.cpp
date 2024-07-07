#include <cstdint>
#include <immintrin.h>
#include <span>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using u32 = std::uint32_t;

#ifdef __AVX512F__
std::vector<u32>
find_newlines_avx2(const char *input, size_t length, u32 reserved_newline_space)
{
  std::vector<u32> result{};
  result.reserve(reserved_newline_space);

  const size_t simd_width = 64;                    // AVX-512 processes 64 bytes at a time
  __m512i newline_vector = _mm512_set1_epi8('\n'); // Set up a vector filled with newline characters

  size_t count = 0;

  for (size_t i = 0; i < length; i += simd_width) {
    // Load 64 bytes from the input
    __m512i chunk = _mm512_loadu_si512((__m512i *)&input[i]);
    // Compare with newline characters
    __mmask64 cmp_mask = _mm512_cmpeq_epi8_mask(chunk, newline_vector);

    // Process the mask
    if (cmp_mask != 0) {
      for (int j = 0; j < simd_width; ++j) {
        if (cmp_mask & (1ULL << j)) {
          result.push_back(i + j);
        }
      }
    }
  }

  return result;
}
#elif defined(__AVX2__)
std::vector<u32>
find_newlines_avx2(const char *input, size_t length, u32 reserved_newline_space)
{
  std::vector<u32> result{};
  result.reserve(reserved_newline_space);

  const size_t simd_width = 32;                          // AVX2 processes 32 bytes at a time
  const __m256i newline_vector = _mm256_set1_epi8('\n'); // Set up a vector filled with newline characters

  size_t count = 0;

  for (size_t i = 0; i < length; i += simd_width) {
    const __m256i chunk = _mm256_loadu_si256((__m256i *)&input[i]);      // Load 32 bytes from the input
    const __m256i cmp_result = _mm256_cmpeq_epi8(chunk, newline_vector); // Compare with newline characters
    const uint32_t mask = _mm256_movemask_epi8(cmp_result); // Create a mask from the comparison results

    if (mask != 0) {
      for (int j = 0; j < simd_width; ++j) {
        if (mask & (1 << j)) {
          result.push_back(i + j);
        }
      }
    }
  }

  return result;
}
#endif

int
main()
{
#ifdef __AVX512F__
  printf("Using AVX512\n");
#elif defined(__AVX2__)
  printf("Using AVX2\n");
#endif

  const char *input = "Hello\nWorld\nThis\nIs\nAVX2Test\nHello\nWorld\nThis\nIsAVX2Test\nHello\nWorld\nThis\nIsAVX"
                      "2\nTest\nHello\nWorld\nThis\nIsAVX2Test\nAAAA\nBBBB\nCCCC";
  size_t length = strlen(input);
  const auto newlines = find_newlines_avx2(input, length, 128);

  printf("Found %zu newlines at positions: ", newlines.size());
  const auto newspan = newlines.size() > 1 ? ({
    printf("%d", *newlines.begin());
    std::span{newlines}.subspan(1);
  })
                                           : std::span<u32>{};

  for (const auto newline_pos : newspan) {
    printf(", %d", newline_pos);
  }
  printf("\n");

  return 0;
}
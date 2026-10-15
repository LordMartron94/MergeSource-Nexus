#include "../nexus.h"

#if defined(NEXUS_PLATFORM_WINDOWS)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(NEXUS_PLATFORM_LINUX) || defined(NEXUS_PLATFORM_ANDROID)
#  include <errno.h>
#  include <stddef.h>
#  include <sys/random.h>
#elif defined(NEXUS_PLATFORM_MACOS) || defined(NEXUS_PLATFORM_IOS) || defined(NEXUS_PLATFORM_BSD)
#  include <errno.h>
#  include <unistd.h>
#endif

/* ---------------------------------------------------------------------------- */
/* GENERATOR PRIMITIVES                                                         */
/* ---------------------------------------------------------------------------- */

#define N_ENTROPY_BUFFER_WORD_OFFSET 32U
#define N_ENTROPY_BUFFER_BYTE_SIZE   64U

static uint32 n_entropy_rotate_left32(uint32 value, uint32 shift) {
  return (value << shift) | (value >> (32U - shift));
}

static uint64 n_entropy_rotate_left64(uint64 value, uint32 shift) {
  return (value << shift) | (value >> (64U - shift));
}

static uint64 n_entropy_splitmix64_next(uint64 *state) {
  uint64 value;

  *state += 0x9e3779b97f4a7c15ULL;
  value = *state;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

static uint32 n_entropy_pcg32_next(NexusEntropyGenerator *generator) {
  uint64 old_state;
  uint32 xor_shifted;
  uint32 rotation;

  old_state           = generator->state[0];
  generator->state[0] = (old_state * 6364136223846793005ULL) + generator->state[1];
  xor_shifted         = (uint32)(((old_state >> 18U) ^ old_state) >> 27U);
  rotation            = (uint32)(old_state >> 59U);

  return (xor_shifted >> rotation) | (xor_shifted << ((0U - rotation) & 31U));
}

static void n_entropy_chacha_quarter_round(uint32 *a, uint32 *b, uint32 *c, uint32 *d) /* NOLINT(readability-identifier-length) */ {
  *a += *b;
  *d ^= *a;
  *d = n_entropy_rotate_left32(*d, 16U);

  *c += *d;
  *b ^= *c;
  *b = n_entropy_rotate_left32(*b, 12U);

  *a += *b;
  *d ^= *a;
  *d = n_entropy_rotate_left32(*d, 8U);

  *c += *d;
  *b ^= *c;
  *b = n_entropy_rotate_left32(*b, 7U);
}

static void n_entropy_chacha_block_generate(NexusEntropyGenerator *generator) {
  uint32 *base;
  uint32 *output;
  uint32  round;
  uint32  word_index;

  base   = (uint32 *)&generator->state[0];
  output = (uint32 *)&generator->state[N_ENTROPY_BUFFER_WORD_OFFSET];

  for (word_index = 0; word_index < 16U; word_index++) {
    output[word_index] = base[word_index];
  }

  for (round = 0; round < generator->rounds; round += 2U) {
    n_entropy_chacha_quarter_round(&output[0], &output[4], &output[8], &output[12]);
    n_entropy_chacha_quarter_round(&output[1], &output[5], &output[9], &output[13]);
    n_entropy_chacha_quarter_round(&output[2], &output[6], &output[10], &output[14]);
    n_entropy_chacha_quarter_round(&output[3], &output[7], &output[11], &output[15]);

    n_entropy_chacha_quarter_round(&output[0], &output[5], &output[10], &output[15]);
    n_entropy_chacha_quarter_round(&output[1], &output[6], &output[11], &output[12]);
    n_entropy_chacha_quarter_round(&output[2], &output[7], &output[8], &output[13]);
    n_entropy_chacha_quarter_round(&output[3], &output[4], &output[9], &output[14]);
  }

  for (word_index = 0; word_index < 16U; word_index++) {
    output[word_index] += base[word_index];
  }

  base[12]++;
  generator->word_index = 0;
}

static uint64 n_entropy_generator_word_next(NexusEntropyGenerator *generator) {
  uint64 state0;
  uint64 state1;
  uint64 result;
  uint32 low;
  uint32 high;

  switch (generator->algorithm) {
  case NEA_LCG64:
    generator->state[0] = (generator->state[0] * 6364136223846793005ULL) + 1442695040888963407ULL;
    return generator->state[0];

  case NEA_SPLITMIX64:
    return n_entropy_splitmix64_next(&generator->state[0]);

  case NEA_XOROSHIRO128:
    state0 = generator->state[0];
    state1 = generator->state[1];
    result = state0 + state1;
    state1 ^= state0;
    generator->state[0] = n_entropy_rotate_left64(state0, 55U) ^ state1 ^ (state1 << 14U);
    generator->state[1] = n_entropy_rotate_left64(state1, 36U);
    return result;

  case NEA_PCG32:
    low  = n_entropy_pcg32_next(generator);
    high = n_entropy_pcg32_next(generator);
    return ((uint64)high << 32U) | (uint64)low;

  case NEA_COUNTER:
    result = generator->state[0];
    generator->state[0] += generator->state[1];
    return result;

  default:
    NEXUS_PROGRAM_PANIC("entropy generator algorithm has no word primitive: %u", (uint32)generator->algorithm);
  }

  return 0;
}

static void n_entropy_word_little_endian_write(uint64 value, byte out_bytes[8]) {
  uint32 byte_index;

  for (byte_index = 0; byte_index < 8U; byte_index++) {
    out_bytes[byte_index] = (byte)(value >> (byte_index * 8U));
  }
}

/* ---------------------------------------------------------------------------- */
/* SOURCES                                                                      */
/* ---------------------------------------------------------------------------- */

NexusEntropySource nexus_entropy_system_source_get(void) {
  NexusEntropySource source;

  source.state = NULL;
  source.fill  = nexus_entropy_system_fill;
  return source;
}

NexusError *nexus_entropy_system_fill(void *state, byte *out_bytes, uint_large byte_count) {
  uint_large offset;
  (void)state;

  NEXUS_PROGRAM_CONTEXT_PUSH("nexus_entropy_system_fill");
  NEXUS_PROGRAM_PRECONDITION(out_bytes != NULL || byte_count == 0, "entropy_system_fill: out_bytes is NULL for nonzero byte_count");

  if (byte_count == 0) {
    NEXUS_PROGRAM_CONTEXT_POP();
    return NEXUS_PROGRAM_ERROR_SUCCESS();
  }

#if defined(NEXUS_PLATFORM_WINDOWS)
  while (byte_count > 0) {
    ULONG    chunk_size;
    NTSTATUS status;

    chunk_size = byte_count > (uint_large)0xffffffffUL ? 0xffffffffUL : (ULONG)byte_count;
    status     = BCryptGenRandom(NULL, (PUCHAR)out_bytes, chunk_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (status < 0) {
      NexusError *error;

      error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_SOURCE_FAILED, "BCryptGenRandom failed with status %ld", (long)status);
      NEXUS_PROGRAM_CONTEXT_POP();
      return error;
    }

    out_bytes += chunk_size;
    byte_count -= chunk_size;
  }
#elif defined(NEXUS_PLATFORM_LINUX) || defined(NEXUS_PLATFORM_ANDROID)
  offset = 0;

  while (offset < byte_count) {
    ssize_t result;

    result = getrandom(out_bytes + offset, (size_t)(byte_count - offset), 0);

    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }

      {
        NexusError *error;

        error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_SOURCE_FAILED, "getrandom failed with errno %d", errno);
        NEXUS_PROGRAM_CONTEXT_POP();
        return error;
      }
    }

    if (result == 0) {
      NexusError *error;

      error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_SOURCE_FAILED, "getrandom returned zero bytes");
      NEXUS_PROGRAM_CONTEXT_POP();
      return error;
    }

    offset += (uint_large)result;
  }
#elif defined(NEXUS_PLATFORM_MACOS) || defined(NEXUS_PLATFORM_IOS) || defined(NEXUS_PLATFORM_BSD)
  offset = 0;

  while (offset < byte_count) {
    uint_large chunk_size;

    chunk_size = byte_count - offset;
    if (chunk_size > 256U) {
      chunk_size = 256U;
    }

    if (getentropy(out_bytes + offset, (size_t)chunk_size) != 0) {
      NexusError *error;

      error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_SOURCE_FAILED, "getentropy failed with errno %d", errno);
      NEXUS_PROGRAM_CONTEXT_POP();
      return error;
    }

    offset += chunk_size;
  }
#else
  {
    NexusError *error;

    error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_SOURCE_FAILED, "no system entropy implementation for this platform");
    NEXUS_PROGRAM_CONTEXT_POP();
    return error;
  }
#endif

  NEXUS_PROGRAM_CONTEXT_POP();
  return NEXUS_PROGRAM_ERROR_SUCCESS();
}

NexusError *nexus_entropy_source_fill(NexusEntropySource source, byte *out_bytes, uint_large byte_count) {
  NexusError *error;

  NEXUS_PROGRAM_CONTEXT_PUSH("nexus_entropy_source_fill");
  NEXUS_PROGRAM_PRECONDITION(source.fill != NULL, "entropy_source_fill: source.fill is NULL");
  NEXUS_PROGRAM_PRECONDITION(out_bytes != NULL || byte_count == 0, "entropy_source_fill: out_bytes is NULL for nonzero byte_count");

  error = source.fill(source.state, out_bytes, byte_count);
  if (error->code != NEXUS_PROGRAM_ERROR_SUCCESS()->code) {
    error = NEXUS_PROGRAM_ERRORS_FORWARD(error);
  }

  NEXUS_PROGRAM_CONTEXT_POP();
  return error;
}

/* ---------------------------------------------------------------------------- */
/* GENERATOR INITIALIZATION                                                     */
/* ---------------------------------------------------------------------------- */

static void n_entropy_generator_clear(NexusEntropyGenerator *generator, NexusEntropyAlgorithm algorithm) {
  NEXUS_PROGRAM_PRECONDITION(generator != NULL, "entropy generator is NULL");

  nexus_memory_bytes_clear(generator, NEXUS_SIZEOF(*generator));
  generator->algorithm  = algorithm;
  generator->word_index = N_ENTROPY_BUFFER_BYTE_SIZE;
}

void nexus_entropy_generator_initialize_lcg64(NexusEntropyGenerator *generator, uint64 seed) {
  n_entropy_generator_clear(generator, NEA_LCG64);
  generator->state[0] = seed;
}

void nexus_entropy_generator_initialize_splitmix64(NexusEntropyGenerator *generator, uint64 seed) {
  n_entropy_generator_clear(generator, NEA_SPLITMIX64);
  generator->state[0] = seed;
}

void nexus_entropy_generator_initialize_xoroshiro128(NexusEntropyGenerator *generator, uint128 seed) {
  n_entropy_generator_clear(generator, NEA_XOROSHIRO128);

  generator->state[0] = seed.lo;
  generator->state[1] = seed.hi;

  if (generator->state[0] == 0 && generator->state[1] == 0) {
    generator->state[0] = 0x9e3779b97f4a7c15ULL;
    generator->state[1] = 0x6a09e667f3bcc909ULL;
  }
}

void nexus_entropy_generator_initialize_pcg32(NexusEntropyGenerator *generator, uint64 seed, uint64 sequence) {
  n_entropy_generator_clear(generator, NEA_PCG32);

  generator->state[0] = 0;
  generator->state[1] = (sequence << 1U) | 1U;
  (void)n_entropy_pcg32_next(generator);
  generator->state[0] += seed;
  (void)n_entropy_pcg32_next(generator);
}

void nexus_entropy_generator_initialize_chacha20(NexusEntropyGenerator *generator, const byte key[32], const byte nonce[12], uint32 counter) {
  static const uint32 constants[4] = {0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
  uint32             *words;
  uint32              index;

  NEXUS_PROGRAM_PRECONDITION(key != NULL, "entropy chacha key is NULL");
  NEXUS_PROGRAM_PRECONDITION(nonce != NULL, "entropy chacha nonce is NULL");

  n_entropy_generator_clear(generator, NEA_CHACHA20);
  generator->rounds = 20U;
  words             = (uint32 *)&generator->state[0];

  for (index = 0; index < 4U; index++) {
    words[index] = constants[index];
  }

  for (index = 0; index < 8U; index++) {
    words[4U + index] = ((uint32)key[(size_t)index * 4U]) | ((uint32)key[(index * 4U) + 1U] << 8U) | ((uint32)key[(index * 4U) + 2U] << 16U) |
                        ((uint32)key[(index * 4U) + 3U] << 24U);
  }

  words[12] = counter;
  for (index = 0; index < 3U; index++) {
    words[13U + index] = ((uint32)nonce[(size_t)index * 4U]) | ((uint32)nonce[(index * 4U) + 1U] << 8U) | ((uint32)nonce[(index * 4U) + 2U] << 16U) |
                         ((uint32)nonce[(index * 4U) + 3U] << 24U);
  }
}

void nexus_entropy_generator_initialize_tape(NexusEntropyGenerator *generator, const void *tape, uint_large tape_length) {
  NEXUS_PROGRAM_PRECONDITION(tape != NULL || tape_length == 0, "entropy tape is NULL for nonzero length");

  n_entropy_generator_clear(generator, NEA_TAPE);
  generator->tape        = (const byte *)tape;
  generator->tape_length = tape_length;
}

void nexus_entropy_generator_initialize_counter(NexusEntropyGenerator *generator, uint64 start, uint64 step) {
  n_entropy_generator_clear(generator, NEA_COUNTER);
  generator->state[0] = start;
  generator->state[1] = step;
}

NexusEntropySource nexus_entropy_generator_source_get(NexusEntropyGenerator *generator) {
  NexusEntropySource source;

  NEXUS_PROGRAM_PRECONDITION(generator != NULL, "entropy generator is NULL");

  source.state = generator;
  source.fill  = nexus_entropy_generator_fill;
  return source;
}

NexusError *nexus_entropy_generator_fill(void *generator_pointer, byte *out_bytes, uint_large byte_count) {
  NexusEntropyGenerator *generator;
  byte                  *buffer;
  uint_large             output_offset;

  NEXUS_PROGRAM_CONTEXT_PUSH("nexus_entropy_generator_fill");
  NEXUS_PROGRAM_PRECONDITION(generator_pointer != NULL, "entropy_generator_fill: generator is NULL");
  NEXUS_PROGRAM_PRECONDITION(out_bytes != NULL || byte_count == 0, "entropy_generator_fill: out_bytes is NULL for nonzero byte_count");

  generator = (NexusEntropyGenerator *)generator_pointer;

  if (generator->algorithm == NEA_TAPE) {
    if (byte_count > generator->tape_length - generator->tape_offset) {
      NexusError *error;

      error = NEXUS_PROGRAM_ERROR_FAILURE(GLOBAL_NEXUS_ENTROPY_ERROR_TAPE_EXHAUSTED, "entropy tape needs %llu bytes but only %llu remain", byte_count,
                                          generator->tape_length - generator->tape_offset);
      NEXUS_PROGRAM_CONTEXT_POP();
      return error;
    }

    if (byte_count > 0) {
      nexus_memory_bytes_copy(generator->tape + generator->tape_offset, out_bytes, byte_count);
      generator->tape_offset += byte_count;
    }

    NEXUS_PROGRAM_CONTEXT_POP();
    return NEXUS_PROGRAM_ERROR_SUCCESS();
  }

  buffer        = (byte *)&generator->state[N_ENTROPY_BUFFER_WORD_OFFSET];
  output_offset = 0;

  while (output_offset < byte_count) {
    uint_large available;
    uint_large copy_count;

    if ((generator->algorithm == NEA_CHACHA20 && generator->word_index >= N_ENTROPY_BUFFER_BYTE_SIZE) ||
        (generator->algorithm != NEA_CHACHA20 && generator->word_index >= 8U)) {
      if (generator->algorithm == NEA_CHACHA20) {
        n_entropy_chacha_block_generate(generator);
      } else {
        uint64 word;

        word = n_entropy_generator_word_next(generator);
        n_entropy_word_little_endian_write(word, buffer);
        generator->word_index = 0;
      }
    }

    available  = generator->algorithm == NEA_CHACHA20 ? N_ENTROPY_BUFFER_BYTE_SIZE - generator->word_index : 8U - generator->word_index;
    copy_count = byte_count - output_offset;
    if (copy_count > available) {
      copy_count = available;
    }

    nexus_memory_bytes_copy(buffer + generator->word_index, out_bytes + output_offset, copy_count);
    generator->word_index += (uint32)copy_count;
    output_offset += copy_count;
  }

  NEXUS_PROGRAM_CONTEXT_POP();
  return NEXUS_PROGRAM_ERROR_SUCCESS();
}

NexusError *nexus_entropy_generator_uint32_get(NexusEntropyGenerator *generator, uint32 *out_value) {
  byte        bytes[4];
  NexusError *error;

  NEXUS_PROGRAM_CONTEXT_PUSH("nexus_entropy_generator_uint32_get");
  NEXUS_PROGRAM_PRECONDITION(generator != NULL, "entropy_generator_uint32_get: generator is NULL");
  NEXUS_PROGRAM_PRECONDITION(out_value != NULL, "entropy_generator_uint32_get: out_value is NULL");

  error = nexus_entropy_generator_fill(generator, bytes, NEXUS_SIZEOF(bytes));
  if (error->code != NEXUS_PROGRAM_ERROR_SUCCESS()->code) {
    error = NEXUS_PROGRAM_ERRORS_FORWARD(error);
    NEXUS_PROGRAM_CONTEXT_POP();
    return error;
  }

  *out_value = (uint32)bytes[0] | ((uint32)bytes[1] << 8U) | ((uint32)bytes[2] << 16U) | ((uint32)bytes[3] << 24U);

  NEXUS_PROGRAM_CONTEXT_POP();
  return NEXUS_PROGRAM_ERROR_SUCCESS();
}

NexusError *nexus_entropy_generator_uint64_get(NexusEntropyGenerator *generator, uint64 *out_value) {
  byte        bytes[8];
  uint32      byte_index;
  NexusError *error;

  NEXUS_PROGRAM_CONTEXT_PUSH("nexus_entropy_generator_uint64_get");
  NEXUS_PROGRAM_PRECONDITION(generator != NULL, "entropy_generator_uint64_get: generator is NULL");
  NEXUS_PROGRAM_PRECONDITION(out_value != NULL, "entropy_generator_uint64_get: out_value is NULL");

  error = nexus_entropy_generator_fill(generator, bytes, NEXUS_SIZEOF(bytes));
  if (error->code != NEXUS_PROGRAM_ERROR_SUCCESS()->code) {
    error = NEXUS_PROGRAM_ERRORS_FORWARD(error);
    NEXUS_PROGRAM_CONTEXT_POP();
    return error;
  }

  *out_value = 0;
  for (byte_index = 0; byte_index < 8U; byte_index++) {
    *out_value |= (uint64)bytes[byte_index] << (byte_index * 8U);
  }

  NEXUS_PROGRAM_CONTEXT_POP();
  return NEXUS_PROGRAM_ERROR_SUCCESS();
}

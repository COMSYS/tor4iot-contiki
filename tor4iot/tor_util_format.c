/* This file contains code taken from the Tor Project ! */

#include "tor_util_format.h"
#include "tor4iot.h"

/* BASE 16 */

/** Helper: given a hex digit, return its value, or -1 if it isn't hex. */
static inline int
hex_decode_digit_(char c)
{
  switch (c) {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': case 'a': return 10;
    case 'B': case 'b': return 11;
    case 'C': case 'c': return 12;
    case 'D': case 'd': return 13;
    case 'E': case 'e': return 14;
    case 'F': case 'f': return 15;
    default:
      return -1;
  }
}

/** Given a hexadecimal string of <b>srclen</b> bytes in <b>src</b>, decode
 * it and store the result in the <b>destlen</b>-byte buffer at <b>dest</b>.
 * Return the number of bytes decoded on success, -1 on failure. If
 * <b>destlen</b> is greater than INT_MAX or less than half of
 * <b>srclen</b>, -1 is returned. */
static int
base16_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *end;
  char *dest_orig = dest;
  int v1,v2;

  if ((srclen % 2) != 0)
    return -1;
  if (destlen < srclen/2 || destlen > INT_MAX)
    return -1;

  /* Make sure we leave no uninitialized data in the destination buffer. */
  memset(dest, 0, destlen);

  end = src+srclen;
  while (src<end) {
    v1 = hex_decode_digit_(*src);
    v2 = hex_decode_digit_(*(src+1));
    if (v1<0||v2<0)
      return -1;
    *(uint8_t*)dest = (v1<<4)|v2;
    ++dest;
    src+=2;
  }

  return (int) (dest-dest_orig);
}

/** Helper: given an extended nickname in <b>hexdigest</b> try to decode it.
 * Return 0 on success, -1 on failure.  Store the result into the
 * DIGEST_LEN-byte buffer at <b>digest_out</b>, the single character at
 * <b>nickname_qualifier_char_out</b>, and the MAXNICKNAME_LEN+1-byte buffer
 * at <b>nickname_out</b>.
 *
 * The recognized format is:
 *   HexName = Dollar? HexDigest NamePart?
 *   Dollar = '?'
 *   HexDigest = HexChar*20
 *   HexChar = 'a'..'f' | 'A'..'F' | '0'..'9'
 *   NamePart = QualChar Name
 *   QualChar = '=' | '~'
 *   Name = NameChar*(1..MAX_NICKNAME_LEN)
 *   NameChar = Any ASCII alphanumeric character
 */
int
hex_digest_nickname_decode(const char *hexdigest,
                           char *digest_out)
{
  if (hexdigest[0] == '$')
    ++hexdigest;

  if (base16_decode(digest_out, DIGEST_LEN,
                    hexdigest, HEX_DIGEST_LEN) != DIGEST_LEN)
    return -1;
  return 0;
}


/* BASE 64 */

/** @{ */
/** Special values used for the base64_decode_table */
#define X 255
#define SP 64
#define PAD 65
/** @} */
/** Internal table mapping byte values to what they represent in base64.
 * Numbers 0..63 are 6-bit integers.  SPs are spaces, and should be
 * skipped.  Xs are invalid and must not appear in base64. PAD indicates
 * end-of-string. */
static const uint8_t base64_decode_table[256] = {
  X, X, X, X, X, X, X, X, X, SP, SP, SP, X, SP, X, X, /* */
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  SP, X, X, X, X, X, X, X, X, X, X, 62, X, X, X, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, X, X, X, PAD, X, X,
  X, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, X, X, X, X, X,
  X, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
  X, X, X, X, X, X, X, X, X, X, X, X, X, X, X, X,
};

/** Base64 decode <b>srclen</b> bytes of data from <b>src</b>.  Write
 * the result into <b>dest</b>, if it will fit within <b>destlen</b>
 * bytes.  Return the number of bytes written on success; -1 if
 * destlen is too short, or other failure.
 *
 * NOTE 1: destlen is checked conservatively, as though srclen contained no
 * spaces or padding.
 *
 * NOTE 2: This implementation does not check for the correct number of
 * padding "=" characters at the end of the string, and does not check
 * for internal padding characters.
 */
int
base64_decode(char *dest, size_t destlen, const char *src, size_t srclen)
{
  const char *eos = src+srclen;
  uint32_t n=0;
  int n_idx=0;
  size_t di = 0;

  if (destlen > INT_MAX)
    return -1;

  /* Make sure we leave no uninitialized data in the destination buffer. */
  memset(dest, 0, destlen);

  /* Iterate over all the bytes in src.  Each one will add 0 or 6 bits to the
   * value we're decoding.  Accumulate bits in <b>n</b>, and whenever we have
   * 24 bits, batch them into 3 bytes and flush those bytes to dest.
   */
  for ( ; src < eos; ++src) {
    unsigned char c = (unsigned char) *src;
    uint8_t v = base64_decode_table[c];
    switch (v) {
      case X:
        /* This character isn't allowed in base64. */
        return -1;
      case SP:
        /* This character is whitespace, and has no effect. */
        continue;
      case PAD:
        /* We've hit an = character: the data is over. */
        goto end_of_loop;
      default:
        /* We have an actual 6-bit value.  Append it to the bits in n. */
        n = (n<<6) | v;
        if ((++n_idx) == 4) {
          /* We've accumulated 24 bits in n. Flush them. */
          if (destlen < 3 || di > destlen - 3)
            return -1;
          dest[di++] = (n>>16);
          dest[di++] = (n>>8) & 0xff;
          dest[di++] = (n) & 0xff;
          n_idx = 0;
          n = 0;
        }
    }
  }
 end_of_loop:
  /* If we have leftover bits, we need to cope. */
  switch (n_idx) {
    case 0:
    default:
      /* No leftover bits.  We win. */
      break;
    case 1:
      /* 6 leftover bits. That's invalid; we can't form a byte out of that. */
      return -1;
    case 2:
      /* 12 leftover bits: The last 4 are padding and the first 8 are data. */
      if (destlen < 1 || di > destlen - 1)
        return -1;
      dest[di++] = n >> 4;
      break;
    case 3:
      /* 18 leftover bits: The last 2 are padding and the first 16 are data. */
      if (destlen < 2 || di > destlen - 2)
        return -1;
      dest[di++] = n >> 10;
      dest[di++] = n >> 2;
  }

  return (int)di;
}
#undef X
#undef SP
#undef PAD

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/hmac.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct bytestring {
  unsigned char bytes[1024];
  size_t length;
} bytestring;

static void bail(const char *err) {
  fprintf(stderr, "ERROR:%s %s\n", err, (errno) ? strerror(errno) : "");
  exit(1);
}

static int b32decode(const char *encoded_str, bytestring *bs) {
  size_t i, len = 0;

  bzero(bs, sizeof(bytestring));
  for (i = 0; encoded_str[i] != '\0' && i < sizeof(bs->bytes); i++) {
    unsigned char x;
    if (isalpha(encoded_str[i])) {
      x = toupper(encoded_str[i]) - 'A';
    } else if (encoded_str[i] >= '2' && encoded_str[i] <= '7') {
      x = encoded_str[i] - '2' + 26;
    } else {
      return 0;
    }
    len = 5 * i / 8;
    bs->bytes[len] |= (x << 3) >> (5 * i % 8);
    if (5 * i % 8 >= 4) {
      len++;
      bs->bytes[len] |= x << (3 + 8 - (5 * i % 8));
    }
  }
  len++;
  bs->length = len;
  return 1;
}

static void hotp(const unsigned char *sbytes, const size_t sbytes_len,
                 const time_t movingFactor, char *code, const size_t code_len) {
  unsigned char data[8];
  unsigned char md[EVP_MAX_MD_SIZE] = {0};
  unsigned int md_len = sizeof(md);
  int i, offset, bin_code, otp;

  for (i = 0; i < 8; i++) {
    data[i] = i < 4 ? 0 : movingFactor >> (56 - 8 * i);
  }
  unsigned char *r =
      HMAC(EVP_sha1(), sbytes, sbytes_len, data, sizeof(data), md, &md_len);
  assert(r);
  offset = r[19] & 0xf;
  assert(offset + 3 < (signed)md_len);
  bin_code = ((r[offset] << 24) | (r[offset + 1] << 16) | (r[offset + 2] << 8) |
              r[offset + 3]) &
             0x7fffffff;
  otp = bin_code % 1000000;
  snprintf(code, code_len, "%06d", otp);
}

static void trim(char *s) {
  char *e;

  e = s + strlen(s) - 1;
  while (isspace(*e) && e > s)
    e--;
  *(e + 1) = '\0';
}

static void check_perms(const char *path) {
  struct stat sb;

  if (stat(path, &sb) == -1) {
    bail(path);
  }
  if ((sb.st_mode & S_IRWXG) || (sb.st_mode & S_IRWXO)) {
    bail("token file must be readable by owner only");
  }
}

static char *get_token_from_file(const char *filename) {
  FILE *tokenfile;
  char path_buf[PATH_MAX];
  char buf[512];
  size_t byte_count;

  bzero(buf, sizeof(buf));
  bzero(path_buf, sizeof(path_buf));

  if (strchr(filename, '/') == NULL) {
    snprintf(path_buf, PATH_MAX, "%s/%s", DEFAULT_TOKEN_PATH, filename);
  } else {
    snprintf(path_buf, PATH_MAX, "%s", filename);
  }
  check_perms(path_buf);
  tokenfile = fopen(path_buf, "r");
  if (!tokenfile) {
    fprintf(stderr, "bad token file: %s\n", path_buf);
    bail("can't open token file:");
  }

  byte_count = fread(buf, sizeof(char), sizeof(buf) - 1, tokenfile);
  fclose(tokenfile);
  if (!byte_count) {
    bail("unable to read token file:");
  }
  buf[byte_count] = '\0';
  trim(buf);
  return strdup(buf);
}

int main(int argc, char *argv[]) {
  char code[7];
  char *token;
  bytestring bs;
  time_t now;

  if (argc < 2) {
    bail("usage: otp [path/to/]tokenfile");
  }
#ifdef __OpenBSD__
  if (pledge("stdio rpath", NULL) == -1) {
    bail("pledge");
  }
#endif

  token = get_token_from_file(argv[1]);

  if (!b32decode(token, &bs)) {
    free(token);
    bail("unable to decode token");
  }

  free(token);

  now = time(NULL);
  hotp(bs.bytes, bs.length, now / 30, code, sizeof(code));

  fprintf(stdout, "%s\n", code);

  return 0;
}

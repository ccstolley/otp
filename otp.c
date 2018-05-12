#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include <openssl/hmac.h>

#ifndef PATH_MAX
 #define PATH_MAX 4096
#endif

static void
bail(const char *err) {
    fprintf(stderr, "ERROR:%s %s\n", err, (errno) ? strerror(errno) : "");
    exit(1);
}

static size_t 
b32decode(const char *s, const size_t s_len, unsigned char *b, size_t b_len)
{
    size_t i;

    if (b_len < 5 * s_len / 8 + 1) {
        bail("key too long");
    }

    bzero(b, b_len);
    for (i = 0; i < s_len; i++) {
        unsigned char x;
        if (isalpha(s[i])) {
            x = toupper(s[i]) - 'A';
        } else if (s[i] >= '2' && s[i] <= '7') {
            x = s[i] - '2' + 26;
        } else {
            return 0;
        }
        b[5 * i / 8] |= (x << 3) >> (5*i % 8);
        if (5 * i % 8 >= 4) {
            b[5 * i / 8 + 1] |= x << (3 + 8 - (5*i % 8));
        }
    }
    return 5 * i / 8;
}

static void 
hotp(const unsigned char *sbytes, const size_t sbytes_len,
     time_t movingFactor, char *code, size_t code_len)
{
    unsigned char data[8];
    int i, offset, bin_code, otp;

    for (i = 0; i < 8; i++) {
        data[i] = i < 4 ? 0 : movingFactor >> (56 - 8*i);
    }
    unsigned char *r = HMAC(EVP_sha1(), sbytes, sbytes_len,
                            data, sizeof(data), NULL, NULL);
    offset = r[19] & 0xf;
    bin_code = ((r[offset] << 24) | (r[offset+1] << 16) |
                (r[offset+2] << 8) | r[offset+3]) & 0x7fffffff;
    otp = bin_code % 1000000;
    snprintf(code, code_len, "%06d", otp);
}

static void
trim(char *s) {
    char *e;

    e = s + strlen(s) - 1;
    while(isspace(*e) && e > s)
        e--;
    *(e + 1) = '\0';
}

static void
check_perms(const char *path) {
    struct stat sb;

    if (stat(path, &sb) == -1) {
        bail(path);
    }
    if ((sb.st_mode & S_IRWXG) || (sb.st_mode & S_IRWXO)) {
        bail("token file must be readable by owner only");
    }
}

static const char *
get_token_from_file(const char *filename) {
    FILE *tokenfile;
    char path_buf[PATH_MAX];
    char buf[512];
    size_t byte_count;

    bzero(buf, sizeof(buf));
    bzero(path_buf, sizeof(path_buf));

    if (strchr(filename, '/') == NULL) {
        snprintf(path_buf, PATH_MAX, "%s/%s", DEFAULT_TOKEN_PATH, filename);
    } else {
        strncpy(path_buf, filename, PATH_MAX);
    }
    check_perms(path_buf);
    tokenfile = fopen(path_buf, "r");
    if (!tokenfile) {
        fprintf(stderr, "bad token file: %s\n", path_buf);
        bail("can't open token file:");
    }

    byte_count = fread(buf, sizeof(char), sizeof(buf) - 1, tokenfile);
    if (!byte_count) {
        bail("unable to read token file:");
    }
    trim(buf);
    return strdup(buf);
}


int main(int argc, char *argv[])
{
    unsigned char sbytes[256];
    size_t sbytes_len;
    char code[7];
    const char *token;
    time_t now;

    if (argc < 2) {
        bail("usage: otp [path/to/]tokenfile");
    }

    token = get_token_from_file(argv[1]);

    sbytes_len = b32decode(token, strlen(token), sbytes, sizeof(sbytes));
    if (!sbytes_len) {
        bail("unable to decode token");
    }

    now = time(NULL);
    hotp(sbytes, sbytes_len, now / 30, code, sizeof(code));

    fprintf(stdout, "%s\n", code);

    return 0;
}

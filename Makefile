VERSION = 1.0
PREFIX = /usr/local

INCS =
LIBS = -lcrypto

DEFINES = -DVERSION=\"${VERSION}\" -DDEFAULT_TOKEN_PATH=\"${PWD}/tokens\"
CFLAGS = -std=gnu99 -fstack-protector-all -fbounds-check -pedantic -Wall -Wextra ${INCS} ${DEFINES} -g
LDFLAGS = ${LIBS}
CC = gcc

SRC = otp.c
OBJ = ${SRC:.c=.o}

all: otp

.c.o:
	${CC} -c ${CFLAGS} $<

otp: ${OBJ}
	${CC} -o $@ $(OBJ) ${LDFLAGS}

clean:
	@echo cleaning
	@rm -f otp ${OBJ} *.core

VERSION = 1.0
PREFIX = /usr/local

INCS =
LIBS = -lcrypto

DEFINES = -DVERSION=\"${VERSION}\" -DDEFAULT_TOKEN_PATH=\"/home/${USER}/software/otp/tokens/\"
CFLAGS = -std=gnu99 -fstack-protector-all -fbounds-check -pedantic -Wall -Wextra ${INCS} ${DEFINES} -g
LDFLAGS = ${LIBS}
CC = gcc

SRC = otp.c
OBJ = ${SRC:.c=.o}

all: otp

.c.o:
	${CC} -c ${CFLAGS} $<

ircl: ${OBJ}
	${CC} -o $@ ${LDFLAGS} ${OBJ} 

clean:
	@echo cleaning
	@rm -f otp ${OBJ} *.core

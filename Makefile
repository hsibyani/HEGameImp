CC = g++
CFLAGS = -g -O2 -Wfatal-errors -Wshadow -Wall -I/usr/local/include -std=c++11
GMP = -lgmp
HEdir = $(HElibdir)
HElib = $(HEdir)/fhe.a

LDLIBS = -L/usr/local/lib $(HElib) -lntl $(GMP) -lm
INCDIR = -I$(HEdir)

HEgame: HEgame.cpp
	$(CC) $(CFLAGS) -o $@ $(INCDIR) $< $(LDLIBS)

clean:
	rm -f HEtest

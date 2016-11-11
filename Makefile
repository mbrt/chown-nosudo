CC=gcc
CFLAGS=-Wall -Wextra
SRCS=chown-nosudo.c

chown-nosudo: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean add-cap add-suid

clean:
	rm -f chown-nosudo

add-cap: chown-nosudo
	sudo chown root:root chown-nosudo
	sudo setcap cap_chown+ep chown-nosudo

add-suid: chown-nosudo
	sudo chown root:root chown-nosudo
	sudo chmod 4755 chown-nosudo

CC=gcc
CFLAGS=
SRCS=chown-nosudo.c

chown-nosudo: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean add-suid

clean:
	rm -f chown-nosudo

add-suid:
	sudo chown root:root chown-nosudo
	sudo chmod 4755 chown-nosudo

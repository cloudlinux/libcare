
all: server


server: server.c
	$(CC) -o $@ $< -fno-stack-protector -fomit-frame-pointer

clean:
	rm -f server

install: server
	mkdir $$DESTDIR || :
	cp server $$DESTDIR

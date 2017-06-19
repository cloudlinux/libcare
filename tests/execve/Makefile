
all: execve.so listener

clean:
	rm -f execve.so listener

execve.so: execve.c
	$(LINK.c) -o $@ $< -shared -fPIC -ldl

listener: listener.c
	$(LINK.c) -o $@ $<


all: execve.so

clean:
	rm -f execve.so

execve.so: execve.c
	$(LINK.c) -o $@ $< -shared -fPIC -ldl

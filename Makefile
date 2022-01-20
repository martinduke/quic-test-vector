all: expand testvector

expand: expand_hex.c
	gcc -o expand expand_hex.c

testvector: testvector.c
	gcc -o testvector testvector.c -lcrypto

clean:
	rm -f expand testvector hex

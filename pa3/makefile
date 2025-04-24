all: detect_dups
	

detect_dups: detect_dups.o
	gcc -Wall -Wextra -O2 -g -I/opt/homebrew/opt/openssl@3/include -o $@ $^ -L/opt/homebrew/opt/openssl@3/lib -lcrypto

detect_dups.o: detect_dups.c detect_dups.h
	gcc -Wall -Wextra -O2 -g -I/opt/homebrew/opt/openssl@3/include -c $<

clean:
	rm -f detect_dups detect_dups.o
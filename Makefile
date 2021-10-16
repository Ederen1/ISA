.PHONY: build

build: main.cpp
	g++ main.cpp -o secret -Wall -Wextra -lcrypto -I /usr/local/lib64
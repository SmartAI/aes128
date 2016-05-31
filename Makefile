all:
	g++ -g *.cpp -o cipher `pkg-config --libs openssl`

clean:
	@rm -rf *.o cipher

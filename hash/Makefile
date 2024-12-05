all: hash_program

hash_program: hash_program.o
	g++ -o hash_program hash_program.o -lcryptopp

hash_program.o: hash_program.cpp
	g++ -c hash_program.cpp -lcryptopp

clean:
	rm -f *.o hash_program

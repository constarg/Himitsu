object_files = ./build/profile.o
header_loc = -I include/


all: dir_make ${object_files}
	g++ -Wall ${header_loc} ./src/main.cpp ${object_files} -o ./bin/pwd_manager

dir_make:
	mkdir -p ./bin/
	mkdir -p ./build/

./build/profile.o: ./src/profile.cpp
	g++ -Wall ${header_loc} -c ./src/profile.cpp -o ./build/profile.o

clean:
	rm -rf ./build/

cleanall:
	rm -rf ./build/
	rm -rf ./bin/

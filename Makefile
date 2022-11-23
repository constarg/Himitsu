object_files = ./build/profile.o
header_loc = -I include/


all: dir_make locations ${object_files}
	g++ -Wall ${header_loc} ./src/main.cpp ${object_files} -lcrypto -o ./bin/pwd_manager

dir_make:
	mkdir -p ./bin/
	mkdir -p ./build/

locations:
	mkdir -p ~/.local/share/pwd_manager --mode=700
	mkdir -p ~/.local/share/pwd_manager/profiles --mode=700
	mkdir -p ~/.local/share/pwd_manager/logins --mode=700

./build/profile.o: ./src/profile.cpp
	g++ -Wall ${header_loc} -c ./src/profile.cpp -lcrypto -o ./build/profile.o

clean:
	rm -rf ./build/

cleanall:
	rm -rf ./build/
	rm -rf ./bin/

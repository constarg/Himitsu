object_files = ./build/profile.o
header_loc = -I include/


all: dir_make locations ${object_files}
	g++ -Wall ${header_loc} ./src/main.cpp ${object_files} -lcrypto -o ./bin/himitsu

install:
	cp ./bin/himitsu ~/.local/bin/	

dir_make:
	mkdir -p ./bin/
	mkdir -p ./build/

locations:
	mkdir -p ~/.local/share/Himitsu 
	mkdir -p ~/.local/share/Himitsu/profiles
	mkdir -p ~/.local/share/Himitsu/logins

./build/profile.o: ./src/profile.cpp
	g++ -Wall ${header_loc} -c ./src/profile.cpp -lcrypto -o ./build/profile.o

clean:
	rm -rf ./build/

cleanall:
	rm -rf ./build/
	rm -rf ./bin/

object_files = ./build/profile.o ./build/security.o
header_loc = -I include/


all: dir_make locations ${object_files}
	g++ -O3 -fvisibility=hidden -Wall ${header_loc} ./src/main.cc ${object_files} -lcrypto -o ./bin/himitsu
	objcopy --localize-hidden --strip-unneeded ./bin/himitsu

debug: dir_make locations ${object_files}
	g++ -g -Wall ${header_loc} ./src/main.cc ${object_files} -lcrypto -o ./bin/himitsu_debug

install:
	cp ./bin/himitsu ~/.local/bin/	

dir_make:
	mkdir -p ./bin/
	mkdir -p ./build/

locations:
	mkdir -p ~/.local/share/Himitsu 
	mkdir -p ~/.local/share/Himitsu/profiles
	mkdir -p ~/.local/share/Himitsu/logins
	mkdir -p ~/.local/share/Himitsu/records

./build/profile.o: ./src/profile.cc
	g++ -O3 -fvisibility=hidden -Wall ${header_loc} -c ./src/profile.cc -lcrypto -o ./build/profile.o

./build/security.o: ./src/security.cc
	g++ -O3 -fvisibility=hidden -Wall ${header_loc} -c ./src/security.cc -lcrypto -o ./build/security.o

clean:
	rm -rf ./build/

cleanall:
	rm -rf ./build/
	rm -rf ./bin/

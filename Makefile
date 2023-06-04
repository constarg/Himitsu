object_files = ./build/profile.o ./build/security.o
object_files_debug = ./build/profile_debug.o ./build/security_debug.o
header_loc = -I include/

GCC = g++

libraries = -lcrypto

c_debug_flags = -O3 -g -Wall -Wpedantic
c_production_flags = -O3 -fvisibility=hidden -Wall -Werror -Wpedantic

obj_flags = --localize-hidden --strip-unneeded


all: dir_make locations ${object_files}
	${GCC} ${c_production_flags} ${header_loc} ./src/main.cc ${object_files} ${libraries} -o ./bin/himitsu
	objcopy ${obj_flags} ./bin/himitsu

debug: dir_make locations ${object_files_debug}
	${GCC} ${c_debug_flags} ${header_loc} ./src/main.cc ${object_files_debug} ${libraries} -o ./bin/himitsu_debug

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
	${GCC} ${c_production_flags} ${header_loc} -c ./src/profile.cc ${libraries} -o ./build/profile.o

./build/security.o: ./src/security.cc
	${GCC} ${c_production_flags} ${header_loc} -c ./src/security.cc ${libraries} -o ./build/security.o

./build/profile_debug.o: ./src/profile.cc
	${GCC} ${c_debug_flags} ${header_loc} -c ./src/profile.cc ${libraries} -o ./build/profile_debug.o

./build/security_debug.o: ./src/security.cc
	${GCC} ${c_debug_flags} ${header_loc} -c ./src/security.cc ${libraries} -o ./build/security_debug.o

clean:
	rm -rf ./build/

cleanall:
	rm -rf ./build/
	rm -rf ./bin/

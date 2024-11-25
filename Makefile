UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	HIDAPI = hidapi-hidraw
else
	HIDAPI = hidapi
endif

CFLAGS += -Wall -Wextra -g -std=gnu99 $(shell pkg-config --cflags $(HIDAPI))
LDFLAGS += $(shell pkg-config --libs $(HIDAPI))
outputs = eizoctl compile_commands.json
ifeq ($(OS),Windows_NT)
	outputs += eizoctltray.png eizoctltray.ico eizoctltray.o eizoctltray.exe
	LDFLAGS += -static
endif

all: $(outputs)
compile_commands.json:
	>$@ echo '[{'
	>>$@ echo '"directory": "'"$$(pwd)"'",'
	>>$@ echo '"command": "$(CC) $(CFLAGS) eizoctl.c",'
	>>$@ echo '"file": "'"$$(pwd)"'/eizoctl.c"'
	>>$@ echo '}]'
eizoctl: eizoctl.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	rm -f $(outputs)

ifeq ($(OS),Windows_NT)
eizoctltray.png: eizoctltray.svg
	rsvg-convert --output=$@ -- $<
eizoctltray.ico: eizoctltray.png
	icotool -c -o $@ -- $<
eizoctltray.o: eizoctltray.rc eizoctltray.ico
	windres -o $@ $<
eizoctltray.exe: eizoctl.c eizoctltray.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -DUNICODE -D_UNICODE -DTRAY \
		-o $@ $^ $(LDFLAGS) -mwindows -municode -lPowrProf
endif

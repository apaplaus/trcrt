COM=g++

CFLAGS=-std=c++11 -pedantic

TARGET=trace

all:$(TARGET)

$(TARGET):$(TARGET).cpp
	$(COM) $(CFLAGS) $< -o $@


backup:
		cp $(TARGET).cpp "./backups/backup."$(TARGET)".cpp($(shell date +%m.%d_%H:%M))"

clean:
	rm -f $(TARGET)

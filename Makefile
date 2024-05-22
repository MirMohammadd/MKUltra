OBJS :=  $(patsubst %.c,%.o,$(wildcard src/*.c)) $(patsubst %.cpp,%.o,$(wildcard src/*.cpp))
SOURCE := mkultra.c
HEADER := 
OUT := mkultra
LFLAGS := -lpthread -I include
CXXFLAGS := -std=c++11 -Wall -I include

CC := gcc
CXX := g++

all: $(OUT)

$(OUT): $(OBJS) $(SOURCE:.c=.o)
	$(CXX) -o $@ $^ $(LFLAGS)

src/%.o: src/%.c
	$(CC) -c -o $@ $< $(LFLAGS)

src/%.o: src/%.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(LFLAGS)

install : all

clean:
	rm -f $(OBJS) $(OUT) $(SOURCE:.c=.o)
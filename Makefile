CXX=g++
CXXFLAGS=-std=c++11 -Wall -Iinclude -Isrc
LIBS=-lgmp -lgmpxx -lpbc 

SRC_DIR=src
SRC=$(wildcard $(SRC_DIR)/*.cpp)
OBJ=$(SRC:.cpp=.o)

TARGET= signtest

MAIN_DIR = .

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) $(MAIN_DIR)/signature.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET) $(MAIN_DIR)/signature.o



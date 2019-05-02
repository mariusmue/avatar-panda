# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# -DUSE_STACK_HEURISTIC tries to detect thread switches by sudden
# jumps in the stack pointer
#LIBS+=-lprotobuf
#CXXFLAGS+="BBBBBBBBBBBBB"
CFLAGS+="-Wno-strict-prototypes"
#CPPFLAGS+="XXXXXXXXXXX"

tmr.pb.h: 
	protoc --proto_path=$(PLUGIN_SRC_DIR) --cpp_out=. $(PLUGIN_SRC_DIR)/tmr.proto

tmr.pb.o: tmr.pb.cc tmr.pb.h
	$(CXX) -c tmr.pb.cc -lprotobuf -lpthread -o tmr.pb.o

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_terrace_tmr.so: tmr.pb.o tmr.pb.h\
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
	


# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# -DUSE_STACK_HEURISTIC tries to detect thread switches by sudden
# jumps in the stack pointer
#LIBS+=

tbb.pb.cc tbb.pb.h: 
	protoc --proto_path=$(PLUGIN_SRC_DIR) --cpp_out=. $(PLUGIN_SRC_DIR)/tbb.proto

obj-y+=tbb.pb.o
# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: tbb.pb.o \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o

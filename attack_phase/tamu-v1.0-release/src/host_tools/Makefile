NAME := host_tools

all:
	cd /host_tools && \
	CARGO_TARGET_DIR=$(TOOLS_OUT_DIR) cargo build --release && \
	cp $(TOOLS_OUT_DIR)/release/enable_tool $(TOOLS_OUT_DIR)/ && \
	cp $(TOOLS_OUT_DIR)/release/package_tool $(TOOLS_OUT_DIR)/ && \
	cp $(TOOLS_OUT_DIR)/release/unlock_tool $(TOOLS_OUT_DIR)/ && \
	cp $(TOOLS_OUT_DIR)/release/pair_tool $(TOOLS_OUT_DIR)/


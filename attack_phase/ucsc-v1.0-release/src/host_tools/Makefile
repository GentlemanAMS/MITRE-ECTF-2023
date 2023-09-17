host_tools: FORCE
	mkdir -p /tmp/bld/host_tools
	cp -r /docker_env /tmp/bld/
	cp -r . /tmp/bld/host_tools
	cd /tmp/bld/host_tools && cargo build --release --out-dir ${TOOLS_OUT_DIR} -Z unstable-options
	mv ${TOOLS_OUT_DIR}/ucsc-ectf-display-unlock-message ${TOOLS_OUT_DIR}/unlock_tool
	mv ${TOOLS_OUT_DIR}/ucsc-ectf-enable-feature ${TOOLS_OUT_DIR}/enable_tool
	mv ${TOOLS_OUT_DIR}/ucsc-ectf-package-feature ${TOOLS_OUT_DIR}/package_tool
	mv ${TOOLS_OUT_DIR}/ucsc-ectf-pair-fob ${TOOLS_OUT_DIR}/pair_tool

FORCE:;

current_dir = $(PWD)
SUBDIRS = src application
.PHONY:all
all:
	@list='$(SUBDIRS)';for subdir in $$list; do \
		cd $$subdir && make && cd $(current_dir); \
	done
	
.PHONY:clean
clean:
	@list='$(SUBDIRS)'; for subdir in $$list; do \
		echo "Clean in $$subdir";\
		cd $$subdir && make clean && cd $(current_dir);\
	done

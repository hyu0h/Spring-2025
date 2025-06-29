src_dir := $(shell pwd)/src
bin_dir := $(shell pwd)/bin
lab1_shared_dir := $(shell pwd)/labs/two_hosts_direct/shared
lab2_shared_dir := $(shell pwd)/labs/six_hosts_two_routers/shared

CC := gcc

all: iperfer

iperfer:
	$(CC) $(src_dir)/iperfer.c -o $(bin_dir)/iperfer
	cp -f $(bin_dir)/iperfer $(lab1_shared_dir)
	cp -f $(bin_dir)/iperfer $(lab2_shared_dir)
clean:
	rm -f $(bin_dir)/iperfer $(lab1_shared_dir)/iperfer $(lab2_shared_dir)/iperfer

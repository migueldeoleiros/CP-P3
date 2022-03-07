all: break_md5.beam

break_md5.beam: break_md5.erl
	erlc +debug_info break_md5.erl

clean:
	rm -f break_md5.beam

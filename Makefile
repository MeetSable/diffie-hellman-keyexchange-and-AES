CC := g++
CFLAGS := -lcrypto -lssl
PARAM_FILE := dhparams.pem
CPP_SOURCE_FILES := dhk.cpp aes.cpp

test:
	$(CC) test.cpp $(CPP_SOURCE_FILES) -o test.out $(CFLAGS)

generate_params:
	$(CC) generate_parameters.cpp $(CPP_SOURCE_FILES) -o gen_param.out $(CFLAGS)
	./gen_param.out "$(PARAM_FILE)"

demo-prog:
	$(CC) $(CPP_SOURCE_FILES) ./demo/receiver/receiver.cpp -I./ -o ./demo/receiver/receiver.out $(CFLAGS)
	$(CC) $(CPP_SOURCE_FILES) ./demo/sender/sender.cpp -I./ -o ./demo/sender/sender.out $(CFLAGS)

clean:
	rm -f $(wildcard *.o */*/*.o *.out */*/*.out)

clean-all:
	rm -f $(wildcard *.o */*/*.o *.out */*/*.out *.pem */*/*.pem *.en */*/*.en *.bin */*/*.bin)
all: server.c
	gcc -pthread -g -Wall -o server server.c 
clean: 
	$(RM) server
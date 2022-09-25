all: server

clean:
	@rm -rf *.o
	@rm -rf server

server: main_arm.o httpd_arm.o
	arm-linux-gnueabi-gcc -fcommon -o server $^

main_arm.o: main.c httpd.h
	arm-linux-gnueabi-gcc -fcommon -c -o main_arm.o main.c

httpd_arm.o: httpd.c httpd.h
	arm-linux-gnueabi-gcc -fcommon -c -o httpd_arm.o httpd.c


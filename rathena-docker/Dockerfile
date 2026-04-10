FROM alpine:3.17.2
WORKDIR /rathena
RUN apk add --no-cache git rsync cmake make gcc g++ gdb zlib-dev mariadb-dev mariadb-client ca-certificates linux-headers bash valgrind netcat-openbsd && \
	git clone https://github.com/rathena/rathena.git . && \
	git checkout b898c9b && \
	./configure --enable-packetver=20200401 && \
	make clean server
CMD /rathena/rathena-start start

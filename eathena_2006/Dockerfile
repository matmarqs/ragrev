# Debian 32-bit (critical for old eAthena)
FROM i386/debian:bullseye

ENV DEBIAN_FRONTEND=noninteractive

# Base build + runtime deps
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    flex \
    bison \
    libmariadb-dev \
    mariadb-server \
    mariadb-client \
    ca-certificates \
    gdb \
    strace \
    nano \
    vim \
    less \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Working directory (mounted as volume later)
WORKDIR /opt/eathena

# MariaDB runtime dir (needed or mysqld won't start)
RUN mkdir -p /run/mysqld && \
    chown -R mysql:mysql /run/mysqld

# RO ports + MySQL
EXPOSE 6900 6121 5121 3306

# Interactive dev shell
CMD ["/bin/bash"]

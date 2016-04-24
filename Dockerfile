FROM centos:7

# install required packages
RUN ["yum", "install", "-y", "epel-release"]
RUN ["yum", "install", "-y", "git", "make", "libtool", "libxml2-devel", "file", "libxslt-devel", "libssh-devel", "libcurl-devel", "python-pip", "libxml2-python", "openssh-server", "augeas-devel" ]
RUN ["ssh-keygen", "-A"]
RUN ["pip", "install", "pyang"]

# clone, build and install libnetconf
RUN set -e -x; \
    git clone https://github.com/CESNET/libnetconf.git /usr/src/libnetconf; \
    cd /usr/src/libnetconf; \
    ./configure --prefix='/usr'; \
    make; \
    make install; \
    ln -s /usr/lib/pkgconfig/libnetconf.pc /usr/lib64/pkgconfig/

# build and install netopeer-server
COPY server /usr/src/netopeer/server
RUN set -e -x; \
    cd /usr/src/netopeer/server; \
    ./configure --prefix='/usr'; \
    make; \
    make install; \
    cp -v config/datastore.xml /usr/etc/netopeer/cfgnetopeer/datastore.xml

# build and install transAPI/cfgsystem
COPY transAPI/cfgsystem /usr/src/netopeer/cfgsystem
RUN set -e -x; \
    cd /usr/src/netopeer/cfgsystem; \
    ./configure --prefix='/usr'; \
    make; \
    make install; \
    sed -i '/<hostname>/d' /usr/etc/netopeer/ietf-system/datastore.xml

CMD ["/usr/bin/netopeer-server", "-v", "2"]

# expose ports
EXPOSE 830

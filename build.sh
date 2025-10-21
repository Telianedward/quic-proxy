перепиши мне этот файл вод это
cd /opt/quic-proxy
rm -rf build
mkdir build && cd build
cmake ..
make -j$(nproc)

sudo systemctl restart quic-proxy.service
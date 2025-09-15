# quic-proxy
```bash
cd /opt
rm -rf quic-proxy
git clone https://github.com/Telianedward/quic-proxy.git
cd quic-proxy
g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread
sudo ./quic_proxy
sudo systemctl daemon-reload
sudo systemctl enable quic-proxy
sudo systemctl start quic-proxy
sudo systemctl status quic-proxy
```


На VPS (Нидерланды):
```bash
cd /opt/quic-proxy
ls -la
```


Если нет `quic_proxy` — собери:
```bash
g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread
```


```bash
sudo ./quic_proxy
```

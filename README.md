# quic-proxy
```bash
cd /opt
rm -rf quic-proxy
git clone https://github.com/Telianedward/quic-proxy.git
cd quic-proxy
g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread
sudo systemctl daemon-reload
sudo systemctl enable quic-proxy.service
sudo systemctl start quic-proxy.service
sudo systemctl status quic-proxy.service
journalctl -u quic-proxy.service -f
```

```bash
cd /opt
cd quic-proxy
sudo systemctl restart quic-proxy.service
sudo systemctl status quic-proxy.service
journalctl -u quic-proxy.service -f
```
sudo systemctl stop quic-proxy.service

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


```bash
cd /opt
rm -rf quic-proxy
git clone https://github.com/Telianedward/quic-proxy.git
cd quic-proxy
g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread
sudo ./quic_proxy
```


```bash
g++ -O2 -o test_udp test_udp.cpp
sudo ./test_udp
````


sudo nano /etc/systemd/system/quic-proxy.service
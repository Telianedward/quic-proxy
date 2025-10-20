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
sudo systemctl restart quic-proxy.service
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


cat > quic_udp_proxy.cpp

rm -rf quic_proxy

g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread


sudo systemctl restart quic-proxy.service
sudo systemctl status quic-proxy.service
journalctl -u quic-proxy.service -f


clear && er -j -f


clear && journalctl -u erosj -f | grep -i "reply\|retry"


clear && journalctl -u quic-proxy.service -f

clear
journalctl -u erosj -f | grep -i "reply\|retry"

# Перейти в директорию проекта
cd /opt/quic-proxy

git clone https://github.com/Telianedward/quic-proxy.git

# Компиляция с C++23
g++ -O2 -std=c++23 -I. -o quic_proxy quic_udp_proxy.cpp -pthread
rm -rf quic_proxy
# Запуск (только от root — нужен доступ к порту 443)
sudo ./quic_proxy
# Сделайте его исполняемым:
cat >  install_quic_proxy.sh

chmod +x install_quic_proxy.sh
# Запустите скрипт с правами root:
sudo ./install_quic_proxy.sh
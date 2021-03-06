ipsec auto --up road-eastnet
ping -W 1 -q -n -c 2 192.0.2.254
ping -W 1 -q -n -c 2 192.1.2.23
ipsec whack --trafficstatus
# note this end should be 192.1.3.209
ip xfrm state
ip xfrm pol
sleep 5
# remove this end ip next one will take over
ip addr show  scope global
ip route
ip route show scope global | grep 192.1.3.254 && ip route del default via 192.1.3.254
ip addr del 192.1.3.209/24 dev eth0 
# removed address and route
sleep 5
ip addr show  scope global
ip route
# add new address and route
ip addr show dev eth0 | grep 192.1.33.222 || ip addr add 192.1.33.222/24 dev eth0
ip route show scope global | grep 192.1.33.254 || ip route add default via 192.1.33.254
# let libreswan detect change and do a MOBIKE update
ping -W 1 -q -n -c 2 -I 192.1.33.222 192.1.2.23
sleep 10
ip addr show  scope global
ip route
# MOBIKE ping should work
# note this end should be 192.1.33.222
ping -W 1 -q -n -c 2 -I 192.1.33.222 192.1.2.23
ping -W 1 -q -n -c 4 192.0.2.254
echo done

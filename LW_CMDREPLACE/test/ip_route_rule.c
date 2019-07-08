ip r a 10.1.1.0/24 via 10.1.1.1 dev eth0 table 231 
ip r a 10.1.1.0/24 via 10.1.4.1 dev eno16777736
ip r d 10.1.1.0/24 via 10.1.1.1 dev eth0 table 231 
ip rule add table 231 prio 1000
ip rule del table 231 prio 1000

ip route replace default nexthop via xxx dev xxx
ip route add xxx via xxx dev xxx
ip route del xxx via xxx dev xxx
ip route del default

gcc lightwanRouteMgmt.c rt_names.c -g -O0 -o RouteMgmt
gcc lightwanRouteMgmt.c -g -O0 -o RouteMgmt

ip route replace default nexthop via 10.1.4.1 dev eno16777736
ip r d 10.1.1.0/24 via 10.1.4.1 dev eno16777736 table 231
ip route list table 231
ip rule list

cp -rf ./test_cp/ test_cp_target/
ls -R test_cp_target/
rm -R ./test_cp_target/test_cp/

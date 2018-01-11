/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add eastnet-any
# this resolv.conf should NOT get modified
ls -l /etc/resolv.conf
echo initdone

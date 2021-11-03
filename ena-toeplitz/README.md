Toepltiz hash ENA
=================

This script output the result of Toepltiz hash that is calculated by ENA HW in
AWS

Usage
=====


Calculate the Toeplitz hash of a packet sent from 1.2.3.4 to 1.2.3.5 with source/destination
port of 7000:

- on an instance that support changing Toeplitz key (only the instance on RX side matters):
  (note that on such instances the key might be randomized by the driver and needs to be
  queried, On Linux the user can use `ethtool -x [interface] command` to fetch it)

```
$ ./toeplitz_calc.py -t 1.2.3.4 -T 7000 -r 1.2.3.5 -R 7000 -k 77:d1:c9:34:a4:c9:bd:87:6e:35:dd:17:b2:e3:23:9e:39:6d:8a:93:2a:95:b4:72:3a:b3:7f:56:8e:de:b6:01:97:af:3b:2f:3a:70:e7:04
```

- on an instance that doesn't support changing Toeplitz key (only the instance on RX side matters):
  (note that on such instances the key is hardcoded in HW, and cannot be changed so there is
  no need to specify it)

```
$ ./toeplitz_calc.py -t 1.2.3.4 -T 7000 -r 1.2.3.5 -R 7000
```

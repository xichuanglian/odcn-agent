# Optical DCN Traffic Monitoring Agent

### Requirements

Required packages for compiling on Ubuntu 14.04:

* Linux headers
```
sudo apt-get install linux-headers-`uname -r`
```

* libnl
```
sudo apt-get install libnl-3-dev libnl-genl-3-dev
```

### Compile & Install Kernel Module

Compile - Execute the following commands in the project directory
```
cd module
make
sudo insmod agent_module.ko
```

Uninstall:
```
sudo rmmod agent_module
```

### Compile & Run Agent

Compile - Execute the following commands in the project directory
```
mkdir bin
make
```

Run:
```
bin/agent -a <server_ip:port> -i <interface> [-v[v]] [-h]
```

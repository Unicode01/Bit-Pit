# Bit-Pit 
[中文](https://github.com/Unicode01/Bit-Pit/blob/main/READMECN.md) | English  
A lightweight private routing and networking tool

# Features
* Connects all servers in a tree topology and automatically creates a private IPv6 network for inter-node communication  
* Supports both IPv4 and IPv6 dual-stack environments  
* Optional TLS encrypted transmission channel  
* Provides a visualized routing monitoring interface (in development)  

# Principles
### Communication Architecture:
The system requires at least two nodes to form a basic service chain:  
1. Upstream Node: Acts as the connection hub and distributes information about downstream nodes  
2. Downstream Node: Actively connects to the upstream node and synchronizes network topology data  
Each upstream node is assigned a unique 8-byte ID during creation, which is used to:  
1. Identify the node’s position in the topology tree  
2. Control the permission to assign IDs to child nodes  

#### Connection Establishment Process:
1. The downstream node sends a connection request and obtains a session token after token validation  
2. The downstream synchronizes the child ID resource pool from the upstream (including ID range and mask information)  
3. Establishes a reverse connection channel  
4. Supports multi-threaded connections (configurable via the `-th` parameter)  
*Note: The root node generates its own ID; non-root node IDs are assigned by their parent node.*

#### Routing Mechanism:
1. Data Routing
    * Automatically determines the destination node’s location when sending data:  
    * If the target is upstream or on the same level: forward via the upstream path  
    * If the target is downstream: directly forward via the downstream path  
    * Supports no-response mode (`noneedresp`) to reduce communication latency  

2. Broadcast Communication (Channel ID 0x0000):
    * Received by all nodes in the network  
    * No response confirmation required  
    * Suitable for scenarios such as network heartbeat checks  

#### Intranet Communication:
* Private subnet: `fd00::/64`  
* IPv6 address generation rule: `fd00::` + LocalID  
Examples:  
  * LocalID 0x01 → `fd00::0100:0:0:0`  
  * LocalID 0x01cc → `fd00::01cc:0:0:0`  
* All communication data is encapsulated and routed through the BPTUN virtual interface using node IDs  

#### Secure Transmission:
* Uses TLS 1.3 for encrypted transmission  
* Currently uses auto-generated self-signed certificates  
* Custom certificate functionality is under development  

# Monitoring System (10% Complete)
* Default monitoring port: listening port + 1  
* Current features:  
  * Real-time network topology display  
  * Node status monitoring  
* Web-based configuration is not yet supported  

# Features to Improve
* Complete routing visualization  
* Custom certificate support  
* Improve auto-reconnect functionality [√]  
* Data statistics [+]  
* Architecture optimization and performance enhancement  
* Smart routing optimization  
* Decouple NodeTree module  
* Improve technical documentation  

# Command Line Parameters
```
Usage of ./Bit-Pit:
  -H string
        remote host (default "127.0.0.1")
  -P int
        remote port (default 18808)
  -Root
        root node
  -T    use TLS
  -debug
        debug mode
  -dws
        disable web server
  -l string
        local host (default "::")
  -p int
        local port (default 18808)
  -t string
        token
  -th int
        Threads for connection (default 1)
```

# Examples
## Root Node
```bash
./Bit-Pit -Root -t 123456 -l :: -p 10888
``` 
This command creates the node as a root node (Token=123456) and opens the local port `::10888` to accept connection requests from other nodes.  
After running, the node's LocalID and private IPv6 address will be displayed.

### Child Node
```bash
./Bit-Pit -H 100.0.0.0 -P 10888 -t 123456 -l :: -p 10888
``` 
This command connects the node to `100.0.0.0:10888` as a child node, and also opens local port `::10888` to accept connection requests from other nodes (only effective when Able2AddChildNode=true).  
After running, the node's LocalID and private IPv6 address will be displayed.

# F&Q
* Is there a Windows version?
  * Due to Golang library limitations, only Linux is supported for now. If the underlying libraries are replaced or ported to Windows in the future, support may change.

* What if the internal NIC's PPS is too low?
  * It’s recommended to increase the number of threads when creating child nodes. Since the underlying protocol is based on TCP, the concurrency isn’t high. It’s not suitable for scenarios with extremely high PPS, which may lead to network congestion.

* How to check routing information?
  * Currently, only visual inspection is supported. You can view routing info by accessing `http://<IP>:<ListenPort+1>` in a browser.

* The logs show many connection errors. Should I be concerned?
  * No need to worry. These are normal connection errors and can be safely ignored.

* If I have a routing structure like:
```
         ServerR  
        /       \  
ServerC1      ServerC2  
```
I need to frequently access ServerC2 from ServerC1, which would go through ServerR. This increases the load on ServerR and response time. What should I do?
  * It's recommended to connect ServerC2 directly to ServerC1 as a child node. This way, communication from ServerC1 to ServerC2 will be direct, avoiding ServerR and reducing response time.

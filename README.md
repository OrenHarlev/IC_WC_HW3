
The firewall module is under the module dir and include the following parts:
- fw : contains all the shred data structs and macros
- FWModule : contains the device/sysfs drivers and the netfilter loading (no actual logic)
- FWPacketParser : parse skbuf to the used structs
- FWPacketMatcher : the main logic to handle a packet (uses all the other modules)
- FWRuleManager : the logic to manage and use the rule table
- FWConnectionManager : the logic to manage and use the tcp connection table
- FWProxyHelper : the logic to decide and modify the packets in order to use the deep inspection proxy
- FWLogger : the logic to manage and use the fw logs


The user space API for managing the firewall is the user/main.py file that exposes the functions as required in ex3 and ex4.


There are 4 proxy server that perform the deep-inspection logic:
1. http_mitm - Blocks DLP and "text/csv", "application/zip" on http protocol (to port 80 only)
2. ftp_mitm - Allows ftp protocol (to port 21 only) communication by updating the connection table with data transfer connection
3. smtp_mitm - Block DLP on smtp protocol (to port 25 only)
4. IPS_mitm - Block the ZooKeeper information disclosure attack (on the specify port).
*Different protection to the Zookepper attack can be used by loading the zookepper_only_rules file to the firewall

All the mitm implementations are based on this open source:
https://github.com/synchronizing/mitm/tree/d9b3a4932eeab6cba68f84338137c4fd254437a9


The DLP capability is based on the Guesslang open source package:
https://github.com/yoeo/guesslang
The logic can be found in mitm.common.utils.is_source_code(data)
And require its prerequisites:
- python 3.6 or above
- TensorFlow 2.2 or above (in order it to work on the 32 bit course vm I used the instructions from this link: https://stackoverflow.com/questions/33634525/tensorflow-on-32-bit-linux)
* If needed I got a version of the project (actually very similar to hw4) submission without the DLP that don't require any complex setups.










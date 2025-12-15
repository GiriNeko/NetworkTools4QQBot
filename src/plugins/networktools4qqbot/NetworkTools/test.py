import network_utils_externel_cpp

print(network_utils_externel_cpp.ping("www.baidu.com", 4))
print(network_utils_externel_cpp.pingv6("::1", 4))
print(network_utils_externel_cpp.tracert("www.baidu.com"))

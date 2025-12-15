#include <asio.hpp>
#include <iostream>
#include <sstream>
#include <chrono>

#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "ping.hpp"

std::string ping(const std::string& dest, std::size_t count)
{
    asio::io_context io_context;
    auto future = asio::co_spawn(io_context, async_ping<ipv4_header>(dest, count), asio::use_future);
    io_context.run();
    if (future.wait_for(std::chrono::nanoseconds(0)) == std::future_status::deferred)
    {
        return "Totally loss";
    }
    std::stringstream ss;
    for (const auto& [ipv4_hdr, icmp_hdr, length, elapsed]: future.get())
    {
        ss << length - ipv4_hdr.header_length()
        << " bytes from " << ipv4_hdr.source_address()
        << ": icmp_seq=" << icmp_hdr.sequence_number()
        << ", ttl=" << ipv4_hdr.time_to_live()
        << ", time="
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
        << "ms\n";
    }
    std::string data = ss.str();
    if (data.empty()) {
        return "Totally lost";
    }
    return data;
}

std::string pingv6(const std::string& dest, std::size_t count)
{
    asio::io_context io_context;
    auto future = asio::co_spawn(io_context, async_ping<ipv6_header>(dest, count), asio::use_future);
    io_context.run();
    if (future.wait_for(std::chrono::nanoseconds(0)) == std::future_status::deferred)
    {
        return "Totally loss";
    }
    std::stringstream ss;
    for (const auto& [_, icmp_hdr, length, elapsed]: future.get())
    {
        ss << length
        << " bytes from " << dest
        << " icmp_seq=" << icmp_hdr.sequence_number()
        << ", time="
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
        << "ms\n";
    }
    std::string data = ss.str();
    if (data.empty()) {
        return "Totally lost";
    }
    return data;
}

int main(){
    std::cout << ping("www.baidu.com", 4) << '\n';
    try {
        std::cout << pingv6("::1", 4) << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
    }
}

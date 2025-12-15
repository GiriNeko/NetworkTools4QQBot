#include <pybind11/pybind11.h>
#include <asio.hpp>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ranges>
#include <format>

#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "ping.hpp"

namespace py = pybind11;

std::string ping(const std::string& dest, int count)
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
        if (!length) {
            ss << "Timeout\n";
        }
        ss << length - ipv4_hdr.header_length()
        << " bytes from " << ipv4_hdr.source_address()
        << " icmp_seq=" << icmp_hdr.sequence_number()
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

std::string pingv6(const std::string& dest, int count)
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
        if (!length) {
            ss << "Timeout\n";
        }
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

py::list tracert(const std::string& dest)
{
    py::list list;
    asio::ip::icmp::endpoint destination;
    {
        asio::io_context io_context;
        asio::ip::icmp::resolver resolver(io_context);
        destination = *resolver.resolve(asio::ip::icmp::v4(), dest, "").begin();
    }
    std::size_t valid_idx = 0;
    for (auto ttl: std::views::iota(1) | std::views::take(30))
    {
        asio::io_context io_context;
        auto future = asio::co_spawn(io_context, async_ping<ipv4_header>(dest, 3, ttl), asio::use_future);
        io_context.run();
        if (future.wait_for(std::chrono::nanoseconds(0)) == std::future_status::deferred)
        {
            continue;
        }
        py::list local_list;
        local_list.append(ttl);
        asio::ip::address address;
        for (const auto& [ipv4_hdr, _1, length, elapsed]: future.get())
        {
            if (address.is_unspecified() && !ipv4_hdr.source_address().is_unspecified()) {
                address = ipv4_hdr.source_address();
            }
            local_list.append(length ? std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() : -1);
        }
        if (!address.is_unspecified()) {
            valid_idx = ttl - 1;
            local_list.append(address.to_string());
        } else {
            local_list.append("timeout");
        }
        list.append(local_list);
        if (address == destination.address() || ttl - valid_idx > 3) {
            break;
        }
    }
    return list;
}

PYBIND11_MODULE(network_utils_externel_cpp, m)
{
    m.doc() = "A Cpp network utils module for python";
    m.def("ping", &ping, "ping the destination");
    m.def("pingv6", &pingv6, "ping the destination in ipv6");
    m.def("tracert", &tracert, "tracert the destination");
}

#pragma once

#include <cstdio>
#include <utility>
#include <iostream>
#include <string>
#include <cstdarg>

#ifdef _WIN32
#include <windows.h>
#endif

namespace ipc {
namespace detail {
template <typename O>
void print(O out, char const * str) {
#ifdef _WIN32
    HANDLE hConsole = (out == stdout) ? GetStdHandle(STD_OUTPUT_HANDLE) : GetStdHandle(STD_ERROR_HANDLE);
    DWORD written;
    WriteConsoleA(hConsole, str, strlen(str), &written, nullptr);
    OutputDebugStringA(str);
#else
    if (out == stdout) {
        std::cout << str;
    } else {
        std::cerr << str;
    }
#endif
}

template <typename O, typename P1, typename... P>
void print(O out, char const * fmt, P1&& p1, P&&... params) {
    constexpr size_t buffer_size = 1024;
    char buffer[buffer_size];
    std::snprintf(buffer, buffer_size, fmt, std::forward<P1>(p1), std::forward<P>(params)...);
    
#ifdef _WIN32
    HANDLE hConsole = (out == stdout) ? GetStdHandle(STD_OUTPUT_HANDLE) : GetStdHandle(STD_ERROR_HANDLE);
    DWORD written;
    WriteConsoleA(hConsole, buffer, strlen(buffer), &written, nullptr);
    OutputDebugStringA(buffer);
#else
    if (out == stdout) {
        std::cout << buffer;
    } else {
        std::cerr << buffer;
    }
#endif
}

} // namespace detail

inline void log(char const * fmt) {
    ipc::detail::print(stdout, fmt);
}

template <typename P1, typename... P>
void log(char const * fmt, P1&& p1, P&&... params) {
    ipc::detail::print(stdout, fmt, std::forward<P1>(p1), std::forward<P>(params)...);
}

inline void error(char const * str) {
    ipc::detail::print(stderr, str);
}

template <typename P1, typename... P>
void error(char const * fmt, P1&& p1, P&&... params) {
    ipc::detail::print(stderr, fmt, std::forward<P1>(p1), std::forward<P>(params)...);
}

} // namespace ipc

// Privacy Shield: A Suite of Tools Designed to Facilitate Privacy Management.
// Copyright (C) 2024  Ian Duncan <dr8co@duck.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see https://www.gnu.org/licenses.

module;

#include <new>
#include <limits>
#include <vector>
#include <sodium.h>
#include <string>

export module secureAllocator;

export namespace privacy {
    template<typename T>
    /// \class Allocator
    /// \brief Custom allocator for STL containers, which locks and zeroizes memory.
    /// \tparam T The type of the elements.
    /// \details Adapted from https://en.cppreference.com/w/cpp/named_req/Allocator
    class Allocator {
    public:
        [[maybe_unused]] typedef T value_type;

        /// Default constructor
        constexpr Allocator() noexcept = default;

        /// Assignment operator
        constexpr Allocator &operator=(const Allocator &) noexcept = default;

        /// Destructor
        ~Allocator() noexcept = default;

        /// Copy constructor
        template<class U>
        constexpr explicit Allocator(const Allocator<U> &) noexcept {}

        /// Allocate memory
        [[maybe_unused]] [[nodiscard]] constexpr T *allocate(std::size_t n) {
            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
                throw std::bad_array_new_length();

            if (auto p = static_cast<T *>(::operator new(n * sizeof(T)))) {
                sodium_mlock(p, n * sizeof(T)); // Lock the allocated memory
                return p;
            }

            throw std::bad_alloc();
        }

        /// Deallocate memory
        [[maybe_unused]] constexpr void deallocate(T *p, std::size_t n) noexcept {
            sodium_munlock(p, n * sizeof(T)); // Unlock and zeroize memory
            ::operator delete(p);
        }
    };

    /// Equality operators
    template<class T, class U>
    [[maybe_unused]] constexpr bool operator==(const Allocator<T> &, const Allocator<U> &) noexcept {
        return true;
    }

    /// Inequality operators
    template<class T, class U>
    [[maybe_unused]] constexpr bool operator!=(const Allocator<T> &, const Allocator<U> &) noexcept {
        return false;
    }

    // Override string and vector types to use our allocator
    using string = std::basic_string<char, std::char_traits<char>, Allocator<char> >;

    template<typename T>
    using vector = std::vector<T, Allocator<T>>;

    using istringstream = std::basic_istringstream<char, std::char_traits<char>, Allocator<char> >;
} // namespace privacy

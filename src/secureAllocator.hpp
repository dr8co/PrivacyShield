#pragma once

#include <new>
#include <limits>
#include <vector>
#include <sodium.h>
#include <string>

namespace privacy {

    template<typename T>
    struct Allocator {
    public:

        [[maybe_unused]] typedef T value_type;

        Allocator() = default;

        // Assignment operator
//        Allocator& operator=(const Allocator&) noexcept = default;

        // Copy constructor
        template<class U>
        constexpr explicit Allocator(const Allocator<U> &) noexcept {}

        [[maybe_unused]] [[nodiscard]] constexpr T *allocate(std::size_t n) {
            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
                throw std::bad_array_new_length();

            if (auto p = static_cast<T *>(::operator new(n * sizeof(T)))) {
                sodium_mlock(p, n * sizeof(T)); // Lock the allocated memory
                return p;
            }

            throw std::bad_alloc();
        }

        [[maybe_unused]] constexpr void deallocate(T *p, std::size_t n) noexcept {
            sodium_munlock(p, n * sizeof(T));  // Unlock and zeroize memory
            ::operator delete(p);
        }
    };

    typedef std::basic_string<char, std::char_traits<char>, Allocator<char> > string;

    template<typename T>
    using vector = std::vector<T, Allocator<T>>;

}  // namespace privacy

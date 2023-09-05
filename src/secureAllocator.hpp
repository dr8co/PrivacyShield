#pragma once

#include <new>
#include <limits>
#include <vector>
#include <sodium.h>
#include <string>

namespace privacy {

    template<typename T>
    /**
     * @brief Custom allocator for STL containers, which locks and zeroizes memory.
     * @details Adapted from https://en.cppreference.com/w/cpp/named_req/Allocator
     */
    struct Allocator {
    public:

        [[maybe_unused]] typedef T value_type;

        // Default constructor
        constexpr Allocator() noexcept = default;

        // Assignment operator
        constexpr Allocator &operator=(const Allocator &) noexcept = default;

        // Destructor
        ~Allocator() noexcept = default;

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

    // Equality operators
    template<class T, class U>
    [[maybe_unused]] constexpr bool operator==(const Allocator<T> &, const Allocator<U> &) noexcept {
        return true;
    }

    // Inequality operators
    template<class T, class U>
    [[maybe_unused]] constexpr bool operator!=(const Allocator<T> &, const Allocator<U> &) noexcept {
        return false;
    }

    // Override string and vector types to use our allocator
    using string = std::basic_string<char, std::char_traits<char>, Allocator<char> >;

    template<typename T>
    using vector = std::vector<T, Allocator<T>>;

    // Assignment between our custom string types
    [[maybe_unused]] constexpr string &assign(string &lhs, const string &rhs) {
        lhs.assign(rhs.begin(), rhs.end());
        return lhs;
    }

    // Assignment between our custom vector types
    template<typename T>
    [[maybe_unused]] constexpr vector<T> &assign(vector<T> &lhs, const vector<T> &rhs) {
        lhs.assign(rhs.begin(), rhs.end());
        return lhs;
    }

    // Assignment between our custom string type and std::string
    [[maybe_unused]] constexpr std::string &assign(std::string &lhs, const string &rhs) {
        lhs.assign(rhs.begin(), rhs.end());
        return lhs;
    }

    // Assignment between our custom vector type and std::vector
    template<typename T>
    [[maybe_unused]] constexpr std::vector<T> &assign(std::vector<T> &lhs, const vector<T> &rhs) {
        lhs.assign(rhs.begin(), rhs.end());
        return lhs;
    }


}  // namespace privacy

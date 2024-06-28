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
#include <mimalloc.h>
#include <array>
#include <vector>
#include <deque>
#include <list>
#include <forward_list>
#include <set>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <stack>
#include <queue>
#include <string>
#include <sstream>

#ifdef __has_include
#if __has_include(<version>)
#include <version> // for feature test macros
#endif

#if __has_include(<flat_set>)
#include <flat_set>
#endif

#if __has_include(<flat_map>)
#include <flat_map>
#endif

#if __has_include(<span>)
#include <span>
#endif

#if __has_include(<mdspan>)
#include <mdspan>
#endif

#if __has_include(<syncstream>)
#include <syncstream>
#endif

#else // __has_include

#if __cpp_lib_flat_set
#include <flat_set>
#endif

#if __cpp_lib_flat_map
#include <flat_map>
#endif

#if __cpp_lib_span
#include <span>
#endif

#if __cpp_lib_mdspan
#include <mdspan>
#endif

#if __cpp_lib_syncbuf
#include <syncstream>
#endif

#endif // __has_include

export module mimallocSTL;

export namespace miSTL {
    /* ********** Sequence Containers ********** */
    // std::array doesn't need a custom allocator, we include it here for completeness
    template<class T, std::size_t N>
    using array = std::array<T, N>;

    // std::vector
    template<class T>
    using vector = std::vector<T, mi_stl_allocator<T> >;

    // std::deque
    template<class T>
    using deque = std::deque<T, mi_stl_allocator<T> >;

    // std::list
    template<class T>
    using list = std::list<T, mi_stl_allocator<T> >;

    // std::forward_list
    template<class T>
    using forward_list = std::forward_list<T, mi_stl_allocator<T> >;

    /* ********** Associative Containers ********** */
    // std::set
    template<class Key, class Compare = std::less<Key> >
    using set = std::set<Key, Compare, mi_stl_allocator<Key> >;

    // std::map
    template<
        class Key,
        class T,
        class Compare = std::less<Key> >
    using map = std::map<Key, T, Compare, mi_stl_allocator<std::pair<const Key, T> > >;

    // std::multiset
    template<
        class Key,
        class Compare = std::less<Key> >
    using multiset = std::multiset<Key, Compare, mi_stl_allocator<Key> >;

    // std::multimap
    template<
        class Key,
        class T,
        class Compare = std::less<Key> >
    using multimap = std::multimap<Key, T, Compare, mi_stl_allocator<std::pair<const Key, T> > >;

    /* ********** Unordered Associative Containers ********** */
    // std::unordered_set
    template<
        class Key,
        class Hash = std::hash<Key>,
        class KeyEqual = std::equal_to<Key> >
    using unordered_set = std::unordered_set<Key, Hash, KeyEqual, mi_stl_allocator<Key> >;

    // std::unordered_map
    template<
        class Key,
        class T,
        class Hash = std::hash<Key>,
        class KeyEqual = std::equal_to<Key> >
    using unordered_map = std::unordered_map<Key, T, Hash, KeyEqual, mi_stl_allocator<std::pair<const Key, T> > >;

    // std::unordered_multiset
    template<
        class Key,
        class Hash = std::hash<Key>,
        class KeyEqual = std::equal_to<Key> >
    using unordered_multiset = std::unordered_multiset<Key, Hash, KeyEqual, mi_stl_allocator<Key> >;

    // std::unordered_multimap
    template<
        class Key,
        class T,
        class Hash = std::hash<Key>,
        class KeyEqual = std::equal_to<Key> >
    using unordered_multimap = std::unordered_multimap<Key, T, Hash, KeyEqual, mi_stl_allocator<std::pair<const Key,
        T> > >;

    /* ********** Container Adaptors ********** */
    // std::stack
    template<class T, class Container = deque<T> >
    using stack = std::stack<T, Container>;

    // std::queue
    template<class T, class Container = deque<T> >
    using queue = std::queue<T, Container>;

    // std::priority_queue
    template<
        class T,
        class Container = vector<T>,
        class Compare = std::less<class Container::value_type> >
    using priority_queue = std::priority_queue<T, Container, Compare>;

    // std::flat_set (C++23)
#if __cpp_lib_flat_set
    template<
        class Key,
        class Compare = std::less<Key>,
        class KeyContainer = vector<Key> >
    using flat_set = std::flat_set<Key, Compare, KeyContainer>;
#endif

    // std::flat_map (C++23)
#if __cpp_lib_flat_map
    template<
        class Key,
        class T,
        class Compare = std::less<Key>,
        class KeyContainer = vector<Key>,
        class MappedContainer = vector<T> >
    using flat_map = std::flat_map<Key, T, Compare, KeyContainer, MappedContainer>;
#endif

    // std::flat_multiset (C++23)
#if __cpp_lib_flat_multiset
    template<
        class Key,
        class Compare = std::less<Key>,
        class KeyContainer = vector<Key> >
    using flat_multiset = std::flat_multiset<Key, Compare, KeyContainer>;
#endif

    // std::flat_multimap (C++23)
#if __cpp_lib_flat_multimap
    template<
        class Key,
        class T,
        class Compare = std::less<Key>,
        class KeyContainer = vector<Key>,
        class MappedContainer = vector<T> >
    using flat_multimap = std::flat_multimap<Key, T, Compare, KeyContainer, MappedContainer>;
#endif

    /* ********** Views ********** */
    // views do not need custom allocators, they are included here for completeness
    // std::span (C++20)
#if __cpp_lib_span
    template<class T, std::size_t Extent = std::dynamic_extent>
    using span = std::span<T, Extent>;
#endif

    // std::mdspan (C++23)
#if __cpp_lib_mdspan
    template<
        class T,
        class Extents,
        class LayoutPolicy = std::layout_right,
        class AccessorPolicy = std::default_accessor<T> >
    using mdspan = std::mdspan<T, Extents, LayoutPolicy, AccessorPolicy>;
#endif

    /* ********** Strings ********** */
    // std::basic_string
    template<class CharT, class Traits = std::char_traits<CharT> >
    using basic_string = std::basic_string<CharT, Traits, mi_stl_allocator<CharT> >;

    // std::string
    using string = basic_string<char>;

    // std::string_view included for completeness, as it doesn't need a custom allocator
    template<class CharT, class Traits = std::char_traits<CharT> >
    using basic_string_view = std::basic_string_view<CharT, Traits>;
    using string_view = basic_string_view<char>;

    /* ********** I/O Streams ********** */
    // std::basic_stringbuf
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_stringbuf = std::basic_stringbuf<CharT, Traits, Allocator>;

    // std::basic_istringstream
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_istringstream = std::basic_istringstream<CharT, Traits, Allocator>;

    // std::basic_ostringstream
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_ostringstream = std::basic_ostringstream<CharT, Traits, Allocator>;

    // std::basic_stringstream
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_stringstream = std::basic_stringstream<CharT, Traits, Allocator>;

    // std::basic_syncbuf
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_syncbuf = std::basic_syncbuf<CharT, Traits, Allocator>;

    // std::basic_osyncstream
    template<
        class CharT,
        class Traits = std::char_traits<CharT>,
        class Allocator = mi_stl_allocator<CharT> >
    using basic_osyncstream = std::basic_osyncstream<CharT, Traits, Allocator>;

    // std::stringbuf
    using stringbuf = basic_stringbuf<char>;

    // std::istringstream
    using istringstream = basic_istringstream<char>;

    // std::stringstream
    using stringstream = basic_stringstream<char>;

    // std::ostringstream
    using ostringstream = basic_ostringstream<char>;

    // std::syncbuf
    using syncbuf = basic_syncbuf<char>;

    // std::osyncstream
    using osyncstream = basic_osyncstream<char>;
} // namespace miSTL

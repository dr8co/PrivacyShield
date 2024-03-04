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

#include <string>
#include <vector>

export module FuzzyMatcher;

import secureAllocator;

template<typename T>
/// \brief A concept describing a range of strings.
/// @tparam T string type.
concept StringRange = std::ranges::input_range<T> &&
                      std::same_as<std::ranges::range_value_t<T>, privacy::string>;

/// \class FuzzyMatcher
/// \brief A simple case insensitive fuzzy matcher.
export class FuzzyMatcher final {
public:
    /// Default constructor
    constexpr FuzzyMatcher() noexcept = default;

    /// Copy constructor
    constexpr FuzzyMatcher(const FuzzyMatcher &) noexcept = default;

    /// Copy assignment operator
    constexpr FuzzyMatcher &operator=(const FuzzyMatcher &) noexcept = default;

    /// Move constructor
    constexpr FuzzyMatcher(FuzzyMatcher &&) noexcept = default;

    /// Move assignment operator
    constexpr FuzzyMatcher &operator=(FuzzyMatcher &&) noexcept = default;

    /// Equality operator
    constexpr bool operator==(const FuzzyMatcher &rhs) const noexcept {
        return stringList == rhs.stringList;
    }

    /// Inequality operator
    constexpr bool operator!=(const FuzzyMatcher &rhs) const noexcept {
        return !(rhs == *this);
    }

    /// \brief Constructs a FuzzyMatcher object, with initialization.
    /// \param wordList the list of strings to be matched against a pattern.
    /// \tparam Range a range of strings.
    /// \note The wordList should be sorted, for deduplication to be successful.
    template<StringRange Range>
    explicit FuzzyMatcher(const Range &wordList) { setStringList(wordList); }

    /// \brief Sets the list of words for fuzzy matching
    /// \tparam Range a range of strings
    /// \param wordList the list of strings to be matched against a pattern.
    template<StringRange Range>
    constexpr void setStringList(const Range &wordList) {
        stringList.reserve(std::ranges::distance(wordList));

        // Copy unique entries to the string list vector (wordList is sorted)
        stringList.emplace_back(*std::ranges::cbegin(wordList));
        for (const auto &el: wordList)
            if (el != stringList.back()) // Deduplicate
                stringList.emplace_back(el);
    }

    /// stringList Getter
    [[maybe_unused]] [[nodiscard]] constexpr const auto &getStringList() const {
        return stringList;
    }

    /// \brief Fuzzy-matches (case insensitive) strings to a pattern.
    /// \param pattern the pattern to match.
    /// \param maxDistance the maximum Levenshtein Distance to consider a match.
    /// \return a vector of strings matching the pattern.
    [[nodiscard]] std::vector<privacy::string> fuzzyMatch(const std::string_view pattern, const int &maxDistance) const {
        std::vector<privacy::string> matches{};
        matches.reserve(stringList.size());  // Worst case: every string in stringList is a match.
        // The maximum and minimum size of a string to be considered a match
        const auto maxSize{pattern.size() + maxDistance + 1};
        const auto minSize{pattern.size() - (maxDistance + 1)};

        // Iterate over the string list and find matches
        for (const auto &str: stringList)
            if (const auto size{str.size()}; size <= maxSize && size >= minSize &&
                                       levenshteinDistance(pattern, str) <= maxDistance)
                matches.emplace_back(str);


        return matches;
    }

    /// Default destructor
    ~FuzzyMatcher() noexcept = default;


private:
    std::vector<privacy::string> stringList{};

    /// \brief Calculates the Levenshtein Distance between two strings.
    /// \param str1 the first string.
    /// \param str2 the second string.
    /// \return the calculated distance.
    /// \note The Levenshtein distance calculated by this function is case insensitive,
    /// i.e the strings are converted to lowercase when calculating the edit distance.
    constexpr static int levenshteinDistance(const std::string_view str1, const std::string_view str2) {
        const int m = static_cast<int>(str1.length());
        const int n = static_cast<int>(str2.length());

        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));

        // Initialize the first row and column
        for (int i = 0; i <= m; ++i)
            dp[i][0] = i;

        for (int j = 0; j <= n; ++j)
            dp[0][j] = j;

        // Calculate the minimum edit distance
        for (int i = 1; i <= m; ++i) {
            for (int j = 1; j <= n; ++j) {
                // If the characters are the same, the cost is 0
                if (std::tolower(str1[i - 1]) == std::tolower(str2[j - 1])) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    // Otherwise, the cost is 1
                    dp[i][j] = 1 + std::min(dp[i - 1][j],   // Deletion
                                            std::min(dp[i][j - 1],  // Insertion
                                                     dp[i - 1][j - 1])     // Substitution
                    );
                }
            }
        }

        // Return the final Levenshtein distance
        return dp[m][n];
    }

};

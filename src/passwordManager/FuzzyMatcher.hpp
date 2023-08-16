#pragma once

#include <string>
#include <vector>
#include <ranges>

template<typename T>
concept StringContainer = std::ranges::input_range<T> &&
                          std::same_as<std::ranges::range_value_t<T>, std::string>;

/**
 * @brief A simple fuzzy matcher.
 */
class FuzzyMatcher {
public:
    template<StringContainer Container>
    explicit FuzzyMatcher(const Container &wordList) : stringList({wordList}) {}

//            : stringList(wordList | std::ranges::to<std::vector>()){} // When the feature becomes available in GCC & Clang

    /**
     * @brief Fuzzy-matches strings to a pattern.
     * @param pattern the pattern to match.
     * @param maxDistance the maximum Levenshtein Distance to consider a match.
     * @return a vector of strings matching the pattern.
     */
    std::vector<std::string> fuzzyMatch(const std::string &pattern, int maxDistance) {
        std::vector<std::string> matches;
        auto maxSize{pattern.size() + maxDistance + 1};

        for (const std::string &str: stringList) {
            if (str.size() <= maxSize) {
                int distance = levenshteinDistance(pattern, str);
                if (distance <= maxDistance) {
                    matches.emplace_back(str);
                }
            }
        }
        return matches;
    }

private:
    std::vector<std::string> stringList;

    /** @brief Finds the minimum of 3 numbers. */
    static constexpr inline int minimum(const int &a, const int &b, const int &c) noexcept {
        return std::min(std::min(a, b), c);
    }

    /**
     * @brief Calculates the Levenshtein Distance between two strings.
     * @param str1 the first string.
     * @param str2 the second string.
     * @return the calculated distance.
     */
    static int levenshteinDistance(const std::string &str1, const std::string &str2) {
        int m = static_cast<int>(str1.length());
        int n = static_cast<int>(str2.length());

        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));

        // Initialize the first row and column
        for (int i = 0; i <= m; ++i)
            dp[i][0] = i;

        for (int j = 0; j <= n; ++j)
            dp[0][j] = j;

        // Calculate the minimum edit distance
        for (int i = 1; i <= m; ++i) {
            for (int j = 1; j <= n; ++j) {
                if (std::tolower(str1[i - 1]) == std::tolower(str2[j - 1])) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + minimum(dp[i - 1][j],     // Deletion
                                           dp[i][j - 1],     // Insertion
                                           dp[i - 1][j - 1]  // Substitution
                    );
                }
            }
        }

        // Return the final Levenshtein distance
        return dp[m][n];
    }

};

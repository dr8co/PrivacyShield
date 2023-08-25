#pragma once

#include <string>
#include <vector>

template<typename T>
/**
 * A concept describing a range of strings.
 * @tparam T string type.
 */
concept StringRange = std::ranges::input_range<T> &&
                      std::same_as<std::ranges::range_value_t<T>, std::string>;


/**
 * @brief A simple case insensitive fuzzy matcher.
 */
class FuzzyMatcher {
public:
    /**
     * @brief Constructs a FuzzyMatcher object.
     * @param wordList the list of strings to be matched against a pattern.
     * @tparam Range a range of strings.
     * @note The wordList should be sorted, for deduplication to be successful.
     */
    template<StringRange Range>
    explicit FuzzyMatcher(const Range &wordList) {
        stringList.reserve(std::ranges::distance(wordList));

        // Copy unique entries to the string list vector (wordList is sorted)
        stringList.emplace_back(*std::ranges::cbegin(wordList));
        for (const auto &el: wordList) {
            if (el != stringList.back())
                stringList.emplace_back(el);
        }
    }

    /**
     * @brief Fuzzy-matches (case insensitive) strings to a pattern.
     * @param pattern the pattern to match.
     * @param maxDistance the maximum Levenshtein Distance to consider a match.
     * @return a vector of strings matching the pattern.
     */
    std::vector<std::string> fuzzyMatch(const std::string &pattern, const int &maxDistance) {
        std::vector<std::string> matches;
        auto maxSize{pattern.size() + maxDistance + 1};

        for (const std::string &str: stringList) {
            if (str.size() <= maxSize) {
                if (levenshteinDistance(pattern, str) <= maxDistance) {
                    matches.emplace_back(str);
                }
            }
        }
        return matches;
    }


private:
    std::vector<std::string> stringList;

    /**
     * @brief Calculates the Levenshtein Distance between two strings.
     * @param str1 the first string.
     * @param str2 the second string.
     * @return the calculated distance.
     * @note The Levenshtein distance calculated by this function is case insensitive,
     * i.e the strings are converted to lowercase when calculating the edit distance.
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

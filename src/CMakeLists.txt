cmake_minimum_required(VERSION 3.25)

# Add sources for the target
target_sources(privacyShield
        PRIVATE main.cpp
        PRIVATE duplicateFinder/duplicateFinder.hpp
        PRIVATE duplicateFinder/duplicateFinder.cpp
        PRIVATE encryption/encryptDecryptFiles.cpp
        PRIVATE encryption/encryptDecryptStrings.cpp
        PRIVATE encryption/encryptDecrypt.cpp
        PRIVATE encryption/encryptDecrypt.hpp
        PRIVATE fileShredder/shredFiles.hpp
        PRIVATE fileShredder/shredFiles.cpp
        PRIVATE passwordManager/passwordManager.cpp
        PRIVATE passwordManager/FuzzyMatcher.hpp
        PRIVATE passwordManager/passwords.hpp
        PRIVATE passwordManager/passwords.cpp
        PRIVATE privacyTracks/privacyTracks.hpp
        PRIVATE privacyTracks/privacyTracks.cpp
        PRIVATE utils/utils.cpp
        PRIVATE utils/utils.hpp
        PRIVATE secureAllocator.hpp)

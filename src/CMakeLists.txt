cmake_minimum_required(VERSION 3.25)


target_sources(privacyShield
        PUBLIC main.cpp
        PUBLIC duplicateFinder/duplicateFinder.hpp
        PUBLIC duplicateFinder/duplicateFinder.cpp
        PUBLIC encryption/encryptDecryptFiles.cpp
        PUBLIC encryption/encryptDecryptStrings.cpp
        PUBLIC encryption/encryptDecrypt.cpp
        PUBLIC encryption/encryptDecrypt.hpp
        PUBLIC fileShredder/shredFiles.hpp
        PUBLIC fileShredder/shredFiles.cpp
        PUBLIC passwordManager/passwordManager.cpp
        PUBLIC passwordManager/FuzzyMatcher.hpp
        PUBLIC passwordManager/passwords.hpp
        PUBLIC passwordManager/passwords.cpp
        PUBLIC privacyTracks/privacyTracks.hpp
        PUBLIC privacyTracks/privacyTracks.cpp
        PUBLIC utils/utils.cpp
        PUBLIC utils/utils.hpp
        PUBLIC secureAllocator.hpp)

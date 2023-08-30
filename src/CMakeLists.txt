cmake_minimum_required(VERSION 3.25)

add_executable(privacyShield
        main.cpp
        duplicateFinder/duplicateFinder.hpp
        duplicateFinder/duplicateFinder.cpp
        encryption/encryptDecryptFiles.cpp
        encryption/encryptDecryptStrings.cpp
        encryption/encryptDecrypt.cpp
        encryption/encryptDecrypt.hpp
        fileShredder/shredFiles.hpp
        fileShredder/shredFiles.cpp
        passwordManager/passwordManager.cpp
        passwordManager/FuzzyMatcher.hpp
        passwordManager/passwords.hpp
        passwordManager/passwords.cpp
        privacyTracks/privacyTracks.hpp
        privacyTracks/privacyTracks.cpp
        utils/utils.cpp
        utils/utils.hpp
        secureAllocator.hpp)

target_link_libraries(privacyShield
        OpenSSL::Crypto
        Readline::readline
        Sodium::sodium
        gcrypt
        blake3)

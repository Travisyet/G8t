QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# Chemins pour libsodium (avec des slashs /, pas de \)
INCLUDEPATH += "C:/Users/latea/Documents/libsodium-1.0.19-mingw/libsodium-win64/include"
LIBS += -L"C:/Users/latea/Documents/libsodium-1.0.19-mingw/libsodium-win64/lib" -lsodium

SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h

FORMS += \
    mainwindow.ui

TARGET = G8t

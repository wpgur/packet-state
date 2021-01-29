TEMPLATE = app
CONFIG += console c++11
LIBS += -lpcap
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp

HEADERS += \
    header.h

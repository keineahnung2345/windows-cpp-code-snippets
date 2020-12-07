#pragma once
#include <stdio.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <Assert.h>
#include <string>
#pragma comment(lib, "iphlpapi.lib")

std::string getMAC();

#include <string>
#include <iostream>
#include <windows.h>

#include "getmac.h"

using namespace std;

int main(int argc, char *argv[])
{
    //get MAC address
    cout << "MAC addr: " << getMAC() << endl;

    system("pause");

    return 0;
}

#include <iostream>

using namespace std;

//https://stackoverflow.com/questions/143174/how-do-i-get-the-directory-that-a-program-is-running-from

int main(){
    char pBuf[256];
    size_t len = sizeof(pBuf); 
    GetModuleFileName(NULL, pBuf, len);
    cout << pBuf << endl;
}

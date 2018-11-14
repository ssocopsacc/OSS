#include <iostream>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
using namespace std;

int main()
{
    char filename[256];
    struct stat fstat;
    int status;

    status = lstat("/etc/localtime", &fstat);
    if (S_ISLNK(fstat.st_mode))
    {
        cout << "/etc/localtime Is a link" << endl;
        int nSize = readlink("/etc/localtime", filename, 256);
        if (nSize > 0)
        {
            filename[nSize] = 0;
            cout << "    linked filename " << filename << endl;
            cout << "    Timezone " << filename + strlen("/usr/share/zoneinfo/") << endl;
        }
    }
    else if (S_ISREG(fstat.st_mode))
        cout << "/etc/localtime Is a file" << endl;
} 

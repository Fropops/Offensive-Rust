#include <iostream>

#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <windows.h>

int g_backed_stdout = 0;
int g_backed_stderr = 0;
HANDLE g_hReadPipe = NULL;
HANDLE g_hWritePipe = NULL;

int RedirectOutputs()
{
    if (GetStdHandle(STD_OUTPUT_HANDLE) == NULL)
    {
        FILE* stream = NULL;
        if (freopen_s(&stream, "NUL", "w", stdout))
            return 3;
        if (freopen_s(&stream, "NUL", "w", stderr))
            return 4;
    }

    //refresh the WINAPI stdout & stderr handles
    if (!SetStdHandle(STD_OUTPUT_HANDLE, reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(stdout)))))
        return 5;
    if (!SetStdHandle(STD_ERROR_HANDLE, reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(stderr)))))
        return 6;

    g_backed_stdout = _dup(_fileno(stdout));
    g_backed_stderr = _dup(_fileno(stderr));

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&g_hReadPipe, &g_hWritePipe, &saAttr, 0))
        return 7;

    FILE* f = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(g_hWritePipe), _O_TEXT), "w");
    if (f == NULL)
        return 8;

    if (_dup2(_fileno(f), _fileno(stdout)) != 0) {
        return 9;
    }

    if (_dup2(_fileno(f), _fileno(stderr)) != 0)  {
        return 10;
    }

    return 0;
}

void RevertOutputs()
{
    if(_dup2(g_backed_stdout, _fileno(stdout)) != 0)
        return;

    if(_dup2(g_backed_stderr, _fileno(stderr)) != 0)
        return;
}

char* ReadOutputs(DWORD *bytesAvailable)  {
        if (!PeekNamedPipe(g_hReadPipe, NULL, NULL, NULL, bytesAvailable, NULL))
            return NULL;

        if (*bytesAvailable == 0)
            return NULL;

        CHAR buffer[512];
        if (!ReadFile(g_hReadPipe, buffer, sizeof(buffer) - 1, bytesAvailable, NULL))
            return NULL;

        return buffer;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)// -> SUBSYSTEM/WINDOWS
//int main() //SUBSYSTEM/CONSOLE
{
    std::cout << "Message in the console (if existing)!\n";

    if (RedirectOutputs() != 0)
    {
        std::cerr << "Failed to redirect outputs!\n";
        return 1;
    }

    std::cout << "This is an STDOUT msg redirected !\n";
    std::cerr << "This is an STDERR msg redirected !\n";

 /*   let mut file = File::create("log.txt").unwrap();
    while let Some(buff) = read_outputs() {
        file.write(&buff).unwrap();
    }*/

    FILE* dataFile;
    if (fopen_s(&dataFile, "data.log", "w") != 0)
        return 2;


    char* c;
    DWORD bytesAvailable = 0;
    while ((c = ReadOutputs(&bytesAvailable)) != NULL)
        _write(_fileno(dataFile), c, bytesAvailable);

    RevertOutputs();

    fclose(dataFile);
    CloseHandle(g_hReadPipe);
    CloseHandle(g_hWritePipe);

    std::cout << "Back in the console (if existing)!\n";

    return 0;
}

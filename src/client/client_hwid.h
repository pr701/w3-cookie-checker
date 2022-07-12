/*
*	Hardware ID Generation
*	pr, 2022
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef __client_hwid__
#define __client_hwid__

#include <cstdint>
#include <string>
#include <sstream>

#include <botan/hash.h>
#include <botan/base64.h>

#include <Windows.h>

namespace client
{

    inline std::string HWID_Init(const std::string& drive)
    {
        char szGuid[MAX_PATH] = { 0 };
        DWORD dwGuidSize = ARRAYSIZE(szGuid);
        DWORD samDesired = KEY_QUERY_VALUE;

#ifndef _WIN64
        samDesired |= KEY_WOW64_64KEY;
#endif

        HKEY hKey;
        if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, samDesired, &hKey))
        {
            DWORD dwType = REG_SZ;
            RegQueryValueExA(hKey, "MachineGuid", NULL, &dwType, (LPBYTE)szGuid, &dwGuidSize);
            RegCloseKey(hKey);
        }

        DWORD dwVolumeSerialNumber = 0;
        GetVolumeInformationA(drive.c_str(), NULL, 0, &dwVolumeSerialNumber, NULL, NULL, NULL, 0);

        std::stringstream serial;
        serial << szGuid << dwVolumeSerialNumber;

        return serial.str();
    }

    inline std::string HWID_Final(const std::string& hwid)
    {
        auto sha1 = Botan::HashFunction::create("SHA-1");

        sha1->update((uint8_t*)hwid.data(), hwid.length());
        return Botan::base64_encode(sha1->final());
    }

    inline std::string HWID_Create(const std::string& drive = "")
    {
        std::string drv = drive;

        if (drive.empty())
        {
            char szPath[8] = { 0 };
            DWORD dwPathSize = ARRAYSIZE(szPath);

            // Get actual drive
            if (!szPath[0])
            {
                // ClientSdk uses GetModuleFileNameW()
                GetModuleFileNameA(NULL, szPath, dwPathSize);
            }
            szPath[3] = 0;

            drv = std::string(szPath);
        }
        return HWID_Final(HWID_Init(drv));
    }
}

#endif

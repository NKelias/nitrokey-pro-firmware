/*
 * Author: Copyright (C) Rudolf Boeddeker  Date: 2013-07-12
 *
 * This file is part of Nitrokey 2
 *
 * Nitrokey 2  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Nitrokey is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Nitrokey. If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * FlashStorage.c
 *
 *  Created on: 12.07.2013
 *      Author: RB
 */

#include <stdlib.h>
#include <stddef.h>
#include "string.h"

#include "delays.h"
#include "FlashStorage.h"
#include "password_safe.h"
#include "hotp.h"
#include "CcidLocalAccess.h"
#include "pbkdf2.h"
#include "memory_ops.h"

typeStick20Configuration_st StickConfiguration_st;


/*******************************************************************************

 Local defines

*******************************************************************************/

unsigned int debug_len = 0;

#define FLASHC_USER_PAGE 0x801dc00

/*

   Userpage layout PAGE: 0x801DC00

   Byte 
   0 - 31     AES Storage key 
   32 - 51    (unused) Matrix columns for user password 
   52 - 71    (unused) Matrix columns for admin password 
   72 - 101   Stick Configuration 
   102 - 133  (unused) Base for AES key hidden volume (32 byte) 
   134 - 137  (unused) ID of sd card (4 byte) 
   138 - 141  (unused) Last stored real timestamp (4 byte)
   142 - 145  (unused) ID of sc card (4 byte) 
   146 - 177  XOR mask for sc tranfered keys (32 byte) 
   178 - 209  Password safe key (32 byte) 
   210 - 242  PBKDF2 Firmware Update password hash (32 byte)
   242 - 251  Firmware Update password Hash salt (10 byte)
   252 - 255  Bootloader boot flag
   256 -      (unused) Debug */

enum user_page_offsets {
    AES_STORAGE_KEY_OFFSET      = 0,
    STICK_CONFIGURATION_OFFSET  = 72,
    XOR_MASK_OFFSET             = 146,
    PWS_KEY_OFFSET              = 178,
    FW_PASSWORD_HASH_OFFSET     = 210,
    FW_SALT_OFFSET              = 242,
    FW_BOOTLOADER_FLAG_OFFSET   = 252,
    DEBUG_OFFSET                = 256
};

#ifdef ADD_DEBUG_COMMANDS

void WriteDebug (uint8_t * data, unsigned int length)
{
    unsigned char page_buffer[FLASH_PAGE_SIZE];

    memcpy (page_buffer, FLASHC_USER_PAGE, FLASH_PAGE_SIZE);
    memcpy (page_buffer + DEBUG_OFFSET, data, length);

    debug_len += length;

    FLASH_Unlock ();
    FLASH_ErasePage (FLASHC_USER_PAGE);
    write_data_to_flash (page_buffer, FLASH_PAGE_SIZE, FLASHC_USER_PAGE);
    FLASH_Lock ();
}


void GetDebug (uint8_t * data, unsigned int* length)
{
    unsigned char page_buffer[FLASH_PAGE_SIZE];

    memcpy (page_buffer, FLASHC_USER_PAGE, FLASH_PAGE_SIZE);
    memcpy (data, page_buffer + DEBUG_OFFSET, debug_len);
    *length = debug_len;
    debug_len = 0;
}

#endif

uint8_t WriteToUserPage(uint8_t * data, uint32_t length, uint32_t offset)
{
    if (offset + length > FLASH_PAGE_SIZE)
    {
        return (FALSE);
    }

    unsigned char page_buffer[FLASH_PAGE_SIZE];

    memcpy (page_buffer, (const void *) FLASHC_USER_PAGE, FLASH_PAGE_SIZE);
    memcpy (page_buffer + offset, data, length);

    FLASH_Unlock ();
    FLASH_ErasePage (FLASHC_USER_PAGE);
    write_data_to_flash (page_buffer, FLASH_PAGE_SIZE, FLASHC_USER_PAGE);
    FLASH_Lock ();

    return (TRUE);
}

#define AES_KEYSIZE_256_BIT     32  // 32 * 8 = 256
#define UPDATE_PIN_MAX_SIZE     20
#define UPDATE_PIN_SALT_SIZE    10

/*******************************************************************************

  WriteAESStorageKeyToUserPage

  Reviews
  Date      Reviewer        Info
  03.02.14  RB              First review

*******************************************************************************/

uint8_t WriteAESStorageKeyToUserPage (uint8_t * data)
{
    return WriteToUserPage (data, AES_KEYSIZE_256_BIT, AES_STORAGE_KEY_OFFSET);
}

/*******************************************************************************

  ReadAESStorageKeyToUserPage

  Reviews
  Date      Reviewer        Info
  16.08.13  RB              First review

*******************************************************************************/

uint8_t ReadAESStorageKeyToUserPage (uint8_t * data)
{
    memcpy (data, (void *) (FLASHC_USER_PAGE), AES_KEYSIZE_256_BIT);
    return (TRUE);
}

/*******************************************************************************

  WriteStickConfigurationToUserPage

  Changes
  Date      Author          Info
  03.02.14  RB              Change to struct

  Reviews
  Date      Reviewer        Info
  16.08.13  RB              First review

*******************************************************************************/

uint8_t WriteStickConfigurationToUserPage (void)
{
    // Set actual firmware version
    // StickConfiguration_st.VersionInfo_au8[0] = VERSION_MAJOR;
    // StickConfiguration_st.VersionInfo_au8[1] = VERSION_MINOR;
    StickConfiguration_st.VersionInfo_au8[2] = 0;   // Build number not used
    StickConfiguration_st.VersionInfo_au8[3] = 0;   // Build number not used

    // flashc_memcpy(FLASHC_USER_PAGE + 72,&StickConfiguration_st,30,TRUE);

    return WriteToUserPage ((uint8_t *) &StickConfiguration_st, sizeof(typeStick20Configuration_st), 72);
}

/*******************************************************************************

  ReadStickConfigurationFromUserPage

  Changes
  Date      Author          Info
  03.02.14  RB              Change to struct

  Reviews
  Date      Reviewer        Info
  16.08.13  RB              First review

*******************************************************************************/

uint8_t ReadStickConfigurationFromUserPage (void)
{
uint8_t UserPwRetryCount;

uint8_t AdminPwRetryCount;

uint32_t ActiveSmartCardID_u32;

    // Save dynamic data
    UserPwRetryCount = StickConfiguration_st.UserPwRetryCount;
    AdminPwRetryCount = StickConfiguration_st.AdminPwRetryCount;
    ActiveSmartCardID_u32 = StickConfiguration_st.ActiveSmartCardID_u32;

    // memcpy (&StickConfiguration_st,(void*)(FLASHC_USER_PAGE + 72),sizeof
    // (typeStick20Configuration_st));

    // Write actual version info
    // StickConfiguration_st.VersionInfo_au8[0] = VERSION_MAJOR;
    // StickConfiguration_st.VersionInfo_au8[1] = VERSION_MINOR;
    StickConfiguration_st.VersionInfo_au8[2] = 0;   // Build number not used
    StickConfiguration_st.VersionInfo_au8[3] = 0;   // Build number not used

    // Restore dynamic data
    StickConfiguration_st.UserPwRetryCount = UserPwRetryCount;
    StickConfiguration_st.AdminPwRetryCount = AdminPwRetryCount;
    StickConfiguration_st.ActiveSmartCardID_u32 = ActiveSmartCardID_u32;

    if (MAGIC_NUMBER_STICK20_CONFIG != StickConfiguration_st.MagicNumber_StickConfig_u16)
    {
        return (FALSE);
    }
    return (TRUE);
}

/*******************************************************************************

  InitStickConfigurationToUserPage_u8

  Changes
  Date      Author          Info
  03.02.14  RB              Function created

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t InitStickConfigurationToUserPage_u8 (void)
{
    StickConfiguration_st.MagicNumber_StickConfig_u16 = MAGIC_NUMBER_STICK20_CONFIG;
    StickConfiguration_st.ReadWriteFlagUncryptedVolume_u8 = READ_WRITE_ACTIVE;
    StickConfiguration_st.ReadWriteFlagCryptedVolume_u8 = READ_WRITE_ACTIVE;
    StickConfiguration_st.ReadWriteFlagHiddenVolume_u8 = READ_WRITE_ACTIVE;
    StickConfiguration_st.FirmwareLocked_u8 = 0;
    StickConfiguration_st.ActiveSD_CardID_u32 = 0;  // todo: check endian
    // StickConfiguration_st.VersionInfo_au8[0] = VERSION_MAJOR;
    // StickConfiguration_st.VersionInfo_au8[1] = VERSION_MINOR;
    StickConfiguration_st.VersionInfo_au8[2] = 0;   // Build number not used
    StickConfiguration_st.VersionInfo_au8[3] = 0;   // Build number not used
    StickConfiguration_st.NewSDCardFound_u8 = 0;
    StickConfiguration_st.SDFillWithRandomChars_u8 = FALSE;
    StickConfiguration_st.VolumeActiceFlag_u8 = 0;
    StickConfiguration_st.NewSmartCardFound_u8 = 0;
    StickConfiguration_st.ActiveSmartCardID_u32 = 0;
    StickConfiguration_st.StickKeysNotInitiated_u8 = TRUE;

    WriteStickConfigurationToUserPage ();

    InitializeUpdatePinHashInFlash ();

    return (TRUE);
}

/*******************************************************************************

  SetSdCardNotFilledWithRandomCharsToFlash

  Bit 0 = 0   SD card is *** not *** filled with random chars
  Bit 0 = 1   SD card is filled with random chars

  Changes
  Date      Author          Info
  06.05.14  RB              Implementation of clear new SD card found

  Reviews
  Date      Reviewer        Info

*******************************************************************************/
#ifdef STORAGE
uint8_t SetSdCardNotFilledWithRandomCharsToFlash (void)
{
    // If configuration not found then init it
    if (FALSE == ReadStickConfigurationFromUserPage ())
    {
        InitStickConfigurationToUserPage_u8 ();
    }

    // CI_LocalPrintf ("Set new SD card *** not *** filled with random
    // chars\r\n");

    StickConfiguration_st.SDFillWithRandomChars_u8 &= 0xFE; // Clear the
    // "card with
    // random chars
    // filled" bit

    WriteStickConfigurationToUserPage ();

    return (TRUE);
}
#endif

/*******************************************************************************

  SetStickKeysNotInitatedToFlash

  Changes
  Date      Author          Info
  05.05.14  RB              Implementation of clear new SD card found

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t SetStickKeysNotInitatedToFlash (void)
{
    // If configuration not found then init it
    if (FALSE == ReadStickConfigurationFromUserPage ())
    {
        InitStickConfigurationToUserPage_u8 ();
    }

    // CI_LocalPrintf ("Set stick keys not initiated\r\n");

    StickConfiguration_st.StickKeysNotInitiated_u8 = TRUE;

    WriteStickConfigurationToUserPage ();

    return (TRUE);
}

/*******************************************************************************

  ClearStickKeysNotInitatedToFlash

  Changes
  Date      Author          Info
  05.05.14  RB              Implementation of clear new SD card found

  Reviews
  Date      Reviewer        Info

*******************************************************************************/
#ifdef STORAGE

uint8_tClearStickKeysNotInitatedToFlash (void)
{
    // If configuration not found then init it
    if (FALSE == ReadStickConfigurationFromUserPage ())
    {
        InitStickConfigurationToUserPage_u8 ();
    }

    // CI_LocalPrintf ("Clear: Stick keys not initiated\r\n");

    StickConfiguration_st.StickKeysNotInitiated_u8 = FALSE;

    WriteStickConfigurationToUserPage ();

    return (TRUE);
}
#endif

/*******************************************************************************

  WriteXorPatternToFlash

  Changes
  Date      Author          Info
  20.05.14  RB              Implementation of save xor pattern to flash

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t WriteXorPatternToFlash (uint8_t* XorPattern_pu8)
{
    return WriteToUserPage (XorPattern_pu8, 32, XOR_MASK_OFFSET);
}

/*******************************************************************************

  ReadXorPatternFromFlash

  Changes
  Date      Author          Info
  20.05.14  RB              Implementation of read xor pattern from flash

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t ReadXorPatternFromFlash (uint8_t* XorPattern_pu8)
{
    memcpy (XorPattern_pu8, (void *) (FLASHC_USER_PAGE + XOR_MASK_OFFSET), 32);

    return (TRUE);
}


/*******************************************************************************

  WritePasswordSafeKey

  Stores the encrypted password safe key

  Byte
  Len = 32 Byte

  Changes
  Date      Author          Info
  01.08.14  RB              Renaming

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t WritePasswordSafeKey (uint8_t* data)
{
    return WriteToUserPage (data, 32, PWS_KEY_OFFSET);
}

/*******************************************************************************

  ReadPasswordSafeKey

  Read the encrypted password safe key

  Changes
  Date      Author          Info
  01.08.14  RB              Renaming


  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t ReadPasswordSafeKey (uint8_t* data)
{
    memcpy (data, (void *) (FLASHC_USER_PAGE + PWS_KEY_OFFSET), 32);
    return (TRUE);
}

/*******************************************************************************

  WriteUpdatePinHashToFlash

  Writes the PBKDF2 hashed Firmware update password to Flash memory

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t WriteUpdatePinHashToFlash (uint8_t* PIN_Hash_pu8)
{
    return WriteToUserPage (PIN_Hash_pu8, 32, FW_PASSWORD_HASH_OFFSET);
}

/*******************************************************************************

  ReadUpdatePinHashFromFlash

  Reads the PBKDF2 hashed Firmware update password from Flash memory

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t ReadUpdatePinHashFromFlash (uint8_t* PIN_Hash_pu8)
{
    memcpy (PIN_Hash_pu8, (void *) (FLASHC_USER_PAGE + FW_PASSWORD_HASH_OFFSET), 32);
    return (TRUE);
}

/*******************************************************************************

  WriteUpdatePinSaltToFlash

  Writes the salt used for PBKDF2 key derivation to Flash memory

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t WriteUpdatePinSaltToFlash (uint8_t* PIN_pu8)
{
    return WriteToUserPage (PIN_pu8, UPDATE_PIN_SALT_SIZE, FW_SALT_OFFSET);
}

/*******************************************************************************

  ReadUpdatePinSaltFromFlash

  Reads the salt used for PBKDF2 key derivation from Flash memory

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t ReadUpdatePinSaltFromFlash (uint8_t* PIN_pu8)
{
    memcpy (PIN_pu8, (void *) (FLASHC_USER_PAGE + FW_SALT_OFFSET), UPDATE_PIN_SALT_SIZE);
    return (TRUE);
}

/*******************************************************************************

  CheckUpdatePin

  Compare the supplied Update Pin with the Update Pin stored in Flash

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t CheckUpdatePin (uint8_t* Password_pu8)
{
    uint8_t i;
    uint8_t UpdateSaltInit;
    uint8_t output_au8[64];
    uint8_t UpdatePinSalt_u8[UPDATE_PIN_SALT_SIZE];
    uint8_t UpdatePinHash_u8[AES_KEYSIZE_256_BIT];

    ReadUpdatePinSaltFromFlash (UpdatePinSalt_u8);

    // Check if PIN is uninitialized after flashing
    UpdateSaltInit = FALSE;
    for (i=0;i<UPDATE_PIN_SALT_SIZE;i++)
    {
      if (0xFF != UpdatePinSalt_u8[i])
      {
        UpdateSaltInit = TRUE;
      }
    }

    if (FALSE == UpdateSaltInit)
    {
        InitializeUpdatePinHashInFlash ();
        ReadUpdatePinSaltFromFlash (UpdatePinSalt_u8);
    }

    pbkdf2 (output_au8, Password_pu8, UPDATE_PIN_MAX_SIZE, UpdatePinSalt_u8, UPDATE_PIN_SALT_SIZE);
    ReadUpdatePinHashFromFlash (UpdatePinHash_u8);

    if (0 != memcmp (UpdatePinHash_u8, output_au8, AES_KEYSIZE_256_BIT))
    {
        return (FALSE);
    }

    // Erase Hash from buffer
    memset_safe(output_au8, 0, UPDATE_PIN_SALT_SIZE);

    DelayMs (100);
    return (TRUE);
}

/*******************************************************************************

  InitializeUpdatePinHashInFlash

  Initializes PIN to default value after Flash erase

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t InitializeUpdatePinHashInFlash ()
{
        uint8_t input_au8[UPDATE_PIN_MAX_SIZE];
        memset (input_au8, 0, UPDATE_PIN_MAX_SIZE);

        // Initialize Update Pin with default value
        strncpy ((char*) input_au8, "12345678", UPDATE_PIN_MAX_SIZE);
        StoreNewUpdatePinHashInFlash (input_au8);
        return (TRUE);
}

/*******************************************************************************

  StoreNewUpdatePinHashInFlash

  Change Firmware Update password stored in Flash

  Changes
  Date      Author          Info
  17.05.19  ET              Merge over from NK Storage

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t StoreNewUpdatePinHashInFlash (uint8_t * Password_pu8)
{
    uint8_t output_au8[64];
    uint8_t UpdatePinSalt_u8[UPDATE_PIN_SALT_SIZE];
    const uint8_t MIN_PASSWORD_LEN = 8;

    // Count trailing zeroes to check if password is >= 8 characters
   for (uint8_t i = UPDATE_PIN_MAX_SIZE -1 ; i >= 0; i--) {
        if (i < MIN_PASSWORD_LEN - 1) {
            return (FALSE);
        }
        if (Password_pu8[i] != 0) {
            break;
        }
    }

    // Generate new salt
    getRandomNumber (UPDATE_PIN_SALT_SIZE, UpdatePinSalt_u8);

    WriteUpdatePinSaltToFlash (UpdatePinSalt_u8);

    pbkdf2 (output_au8, Password_pu8, UPDATE_PIN_MAX_SIZE, UpdatePinSalt_u8, UPDATE_PIN_SALT_SIZE);
    WriteUpdatePinHashToFlash (output_au8);

    memset_safe(output_au8, 0, UPDATE_PIN_SALT_SIZE);

    return (TRUE);
}

/*******************************************************************************

  WriteBootloaderFlagToFlash

  Writes the Flag for bootloader invocation to flash memory

  Changes
  Date      Author          Info
  21.05.19  ET              Add function

  Reviews
  Date      Reviewer        Info

*******************************************************************************/

uint8_t WriteBootloaderFlagToFlash (void)
{
    const uint32_t BOOTLOADER_TOKEN = 0x424F4F54; // "BOOT" in Hex

    return WriteToUserPage ((uint8_t *) BOOTLOADER_TOKEN, sizeof(uint32_t), FW_BOOTLOADER_FLAG_OFFSET);
}

/*******************************************************************************

  EraseBootloaderFlagFromFlash

  Erases bootloader flag to boot straight into firmware

  Changes
  Date      Author          Info
  21.05.19  ET              Add function

*******************************************************************************/

uint8_t EraseBootloaderFlagFromFlash (void)
{
    const uint32_t EMPTY_TOKEN = 0xFFFFFFFF; // "BOOT" in Hex

    return WriteToUserPage ((uint8_t *) EMPTY_TOKEN, sizeof(uint32_t), FW_BOOTLOADER_FLAG_OFFSET);
}

/*******************************************************************************

  EraseLocalFlashKeyValues_u32

  Changes
  Date      Author          Info
  10.09.14  RB              Implementation


  Reviews
  Date      Reviewer        Info

*******************************************************************************/

#if (defined __GNUC__) && (defined __AVR32__)
__attribute__ ((__aligned__ (4)))
#elif (defined __ICCAVR32__)
#pragma data_alignment = 4
#endif
uint8_t EraseStoreData_au8[256];

uint32_t EraseLocalFlashKeyValues_u32 (void)
{
uint32_t i;

uint32_t i1;

uint8_t page_buffer[FLASH_PAGE_SIZE];

    // Clear user page
    for (i1 = 0; i1 < 7; i1++)
    {
        for (i = 0; i < 256; i++)
        {
            EraseStoreData_au8[i] = (u8) (rand () % 256);
        }
        // flashc_memcpy((void*)FLASHC_USER_PAGE,EraseStoreData_au8,256,TRUE);
        WriteToUserPage (EraseStoreData_au8, 256, 0);
    }

    // flashc_erase_user_page (TRUE);

    // Set default values
    InitStickConfigurationToUserPage_u8 ();

    // DFU_DisableFirmwareUpdate (); // Stick always starts in application
    // mode
    // CheckForNewSdCard (); // Get SD ID

    // Clear password safe

    for (i1 = 0; i1 < 7; i1++)
    {
        for (i = 0; i < 256; i++)
        {
            EraseStoreData_au8[i] = (u8) (rand () % 256);
        }
        // flashc_memcpy((void*)(PWS_FLASH_START_ADDRESS
        // ),EraseStoreData_au8,256,TRUE);
        // flashc_memcpy((void*)(PWS_FLASH_START_ADDRESS+256),EraseStoreData_au8,256,TRUE);

        // memcpy(page_buffer, PWS_FLASH_START_ADDRESS, FLASH_PAGE_SIZE);
        memcpy (page_buffer, EraseStoreData_au8, 256);
        memcpy (page_buffer + 256, EraseStoreData_au8, 256);
        FLASH_Unlock ();
        FLASH_ErasePage (PWS_FLASH_START_ADDRESS);
        write_data_to_flash (page_buffer, FLASH_PAGE_SIZE, PWS_FLASH_START_ADDRESS);
        FLASH_Lock ();

    }


    // flashc_erase_page(PWS_FLASH_START_PAGE,TRUE);

    // Clear OTP
    for (i1 = 0; i1 < 7; i1++)
    {
        for (i = 0; i < 256; i++)
        {
            EraseStoreData_au8[i] = (u8) (rand () % 256);
        }
        for (i = 0; i < 10; i++)
        {
            // flashc_memcpy((void*)(SLOTS_ADDRESS+i*512
            // ),EraseStoreData_au8,256,TRUE);
            // flashc_memcpy((void*)(SLOTS_ADDRESS+i*512+256),EraseStoreData_au8,256,TRUE);
            // TODO:
            // write_data_to_flash ( EraseStoreData_au8, 256, SLOTS_ADDRESS +
            // i*512);
            // write_data_to_flash ( EraseStoreData_au8, 256, SLOTS_ADDRESS +
            // i*512 + 256);
        }
    }

    for (i = 0; i < 10; i++)
    {
        // flashc_erase_page(OTP_FLASH_START_PAGE+i,TRUE);
    }

    return (TRUE);
}

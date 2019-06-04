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
 * FlashStorage.h
 *
 *  Created on: 12.07.2013
 *      Author: RB
 */

#ifndef FLASHSTORAGE_H_
#define FLASHSTORAGE_H_

#include "stm32f10x.h"

uint8_t WriteAESStorageKeyToUserPage (uint8_t * data);

uint8_t WriteStickConfigurationToUserPage (void);

uint8_t ReadStickConfigurationFromUserPage (void);

uint8_t InitStickConfigurationToUserPage_u8 (void);

uint32_t EraseLocalFlashKeyValues_u32 (void);

/***************************************************************************************

  Structure is also send to GUI

***************************************************************************************/

#define MAGIC_NUMBER_STICK20_CONFIG     0x1810  // Change when
                                                // typeStick20Configuration_st
                                                // is changed

#define READ_WRITE_ACTIVE             0
#define READ_ONLY_ACTIVE              1

#define SD_UNCRYPTED_VOLUME_BIT_PLACE   0
#define SD_CRYPTED_VOLUME_BIT_PLACE     1
#define SD_HIDDEN_VOLUME_BIT_PLACE      2

/*
   #if (defined __GNUC__) && (defined __AVR32__) __attribute__((__aligned__(4))) #elif (defined __ICCAVR32__) #pragma data_alignment = 4 #endif */
/* Look for 4 byte alignment of 32 bit values */
typedef struct
{
    u16 MagicNumber_StickConfig_u16;    // Shows that the structure is valid
    // 2 byte // 2
    uint8_t ReadWriteFlagUncryptedVolume_u8; // Flag stores the read/write flag in
    // the CPU flash 1 byte // 3
    uint8_t ReadWriteFlagCryptedVolume_u8;   // Flag stores the read/write flag in
    // the CPU flash 1 byte // 4
    uint8_t VersionInfo_au8[4];      // 4 byte // 8
    uint8_t ReadWriteFlagHiddenVolume_u8;    // Flag stores the read/write flag in
    // the CPU flash 1 byte // 9
    uint8_t FirmwareLocked_u8;       // 1 byte // 10
    uint8_t NewSDCardFound_u8;       // Bit 0 new card found, bit 1-7 change counter 1
    // byte // 11
    uint8_t SDFillWithRandomChars_u8;    // Bit 0 = 1 = filled, bit 1-7 change
    // counter 1 byte // 12
    uint32_t ActiveSD_CardID_u32;    // 4 byte // 16
    uint8_t VolumeActiceFlag_u8;     // 1 byte // 17
    uint8_t NewSmartCardFound_u8;    // Bit 0 new card found, bit 1-7 change
    // counter 1 byte
    uint8_t UserPwRetryCount;        // User password retry count 1 byte // 19
    uint8_t AdminPwRetryCount;       // Admin password retry count 1 byte // 20 Byte
    // not packed
    uint32_t ActiveSmartCardID_u32;  // 4 byte
    uint8_t StickKeysNotInitiated_u8;    // No AES keys computed (1 = AES are
    // builded) 1 byte // 25 Byte not packed
} typeStick20Configuration_st;  // Sum 25 byte (Max 25 Byte) // not packed


extern typeStick20Configuration_st StickConfiguration_st;

uint8_t WriteToUserPage(uint8_t * data, uint32_t length, uint32_t offset);

uint8_t WriteXorPatternToFlash (uint8_t * XorPattern_pu8);
uint8_t ReadXorPatternFromFlash (uint8_t * XorPattern_pu8);

uint8_t WritePasswordSafeKey (uint8_t * data);

uint8_t ReadPasswordSafeKey (uint8_t * data);
uint8_t ReadAESStorageKeyToUserPage (uint8_t * data);

uint8_t WriteUpdatePinHashToFlash (uint8_t * PIN_Hash_pu8);
uint8_t ReadUpdatePinHashFromFlash (uint8_t * PIN_Hash_pu8);
uint8_t WriteUpdatePinSaltToFlash (uint8_t * PIN_pu8);
uint8_t ReadUpdatePinSaltFromFlash (uint8_t * PIN_pu8);

uint8_t CheckUpdatePin (uint8_t * Password_pu8);
uint8_t InitializeUpdatePinHashInFlash (void);
uint8_t StoreNewUpdatePinHashInFlash (uint8_t * Password_pu8);

uint8_t WriteBootloaderFlagToFlash (void);
uint8_t EraseBootloaderFlagFromFlash (void);


uint8_t ClearStickKeysNotInitatedToFlash (void);
uint8_t SetStickKeysNotInitatedToFlash (void);

#endif /* FLASHSTORAGE_H_ */

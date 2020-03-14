//
//  devices.cpp
//  itlwm
//
//  Created by qcwap on 2020/3/13.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "devices.hpp"

#define IWM7260_FW    "iwlwifi-7260-16.ucode"
#define IWM3160_FW    "iwlwifi-3160-16.ucode"
#define IWM3168_FW    "iwlwifi-3168-27.ucode"
#define IWM7265_FW    "iwlwifi-7265-16.ucode"
#define IWM7265D_FW    "iwlwifi-7265D-27.ucode"
#define IWM8000_FW    "iwlwifi-8000C-34.ucode"
#define IWM8265_FW    "iwlwifi-8265-34.ucode"
#define IWM9000_FW    "iwlwifi-9000-pu-b0-jf-b0-43.ucode"
#define IWM9260_FW    "iwlwifi-9260-th-b0-jf-b0-33.ucode"

#define IWM_NVM_HW_SECTION_NUM_FAMILY_7000    0
#define IWM_NVM_HW_SECTION_NUM_FAMILY_8000    10
#define IWM_NVM_HW_SECTION_NUM_FAMILY_9000    10
#define IWM_NVM_HW_SECTION_NUM_FAMILY_9260    10

#define IWM_DEVICE_7000_COMMON                        \
.device_family = IWM_DEVICE_FAMILY_7000,            \
.eeprom_size = IWM_OTP_LOW_IMAGE_SIZE_FAMILY_7000,        \
.nvm_hw_section_num = IWM_NVM_HW_SECTION_NUM_FAMILY_7000,    \
.apmg_wake_up_wa = 1

#define IWM_DEVICE_8000_COMMON                        \
.device_family = IWM_DEVICE_FAMILY_8000,            \
.eeprom_size = IWM_OTP_LOW_IMAGE_SIZE_FAMILY_8000,        \
.nvm_hw_section_num = IWM_NVM_HW_SECTION_NUM_FAMILY_8000

#define IWM_DEVICE_9000_COMMON                        \
.device_family = IWM_DEVICE_FAMILY_9000,            \
.eeprom_size = IWM_OTP_LOW_IMAGE_SIZE_FAMILY_9000,        \
.nvm_hw_section_num = IWM_NVM_HW_SECTION_NUM_FAMILY_9000

#define IWM_DEVICE_9260_COMMON                        \
.device_family = IWM_DEVICE_FAMILY_9000,            \
.eeprom_size = IWM_OTP_LOW_IMAGE_SIZE_FAMILY_9000,        \
.nvm_hw_section_num = IWM_NVM_HW_SECTION_NUM_FAMILY_9260

const struct iwm_cfg iwm7260_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 7260",
    .fw_name = IWM7260_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 1,
};

const struct iwm_cfg iwm3160_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 3160",
    .fw_name = IWM3160_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 1,
};

const struct iwm_cfg iwm3165_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 3165",
    .fw_name = IWM7265D_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 0,
};

const struct iwm_cfg iwm3168_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 3168",
    .fw_name = IWM3168_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 0,
    .nvm_type = IWM_NVM_SDP,
};

const struct iwm_cfg iwm7265_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 7265",
    .fw_name = IWM7265_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 0,
};

const struct iwm_cfg iwm7265d_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 7265",
    .fw_name = IWM7265D_FW,
    IWM_DEVICE_7000_COMMON,
    .host_interrupt_operation_mode = 0,
};

const struct iwm_cfg iwm8260_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 8260",
    .fw_name = IWM8000_FW,
    IWM_DEVICE_8000_COMMON,
    .host_interrupt_operation_mode = 0,
};

const struct iwm_cfg iwm8265_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 8265",
    .fw_name = IWM8265_FW,
    IWM_DEVICE_8000_COMMON,
    .host_interrupt_operation_mode = 0,
};

const struct iwm_cfg iwm9560_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 9560",
    .fw_name = IWM9000_FW,
    IWM_DEVICE_9000_COMMON,
    .host_interrupt_operation_mode = 0,
    .mqrx_supported = 1,
    .integrated = 1,
};

const struct iwm_cfg iwm9260_cfg = {
    .name = "Intel(R) Dual Band Wireless AC 9260",
    .fw_name = IWM9260_FW,
    IWM_DEVICE_9260_COMMON,
    .host_interrupt_operation_mode = 0,
    .mqrx_supported = 1,
};

//
//  devices.hpp
//  itlwm
//
//  Created by qcwap on 2020/3/13.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef devices_hpp
#define devices_hpp

#include "types.h"

enum iwm_device_family {
    IWM_DEVICE_FAMILY_UNDEFINED,
    IWM_DEVICE_FAMILY_7000,
    IWM_DEVICE_FAMILY_8000,
    IWM_DEVICE_FAMILY_9000,
};

#define IWM_DEFAULT_MAX_TX_POWER    22

/* Antenna presence definitions */
#define    IWM_ANT_NONE    0x0
#define    IWM_ANT_A    (1 << 0)
#define    IWM_ANT_B    (1 << 1)
#define IWM_ANT_C    (1 << 2)
#define    IWM_ANT_AB    (IWM_ANT_A | IWM_ANT_B)
#define    IWM_ANT_AC    (IWM_ANT_A | IWM_ANT_C)
#define IWM_ANT_BC    (IWM_ANT_B | IWM_ANT_C)
#define IWM_ANT_ABC    (IWM_ANT_A | IWM_ANT_B | IWM_ANT_C)

static inline uint8_t num_of_ant(uint8_t mask)
{
    return  !!((mask) & IWM_ANT_A) +
        !!((mask) & IWM_ANT_B) +
        !!((mask) & IWM_ANT_C);
}

/* lower blocks contain EEPROM image and calibration data */
#define IWM_OTP_LOW_IMAGE_SIZE_FAMILY_7000    (16 * 512 * sizeof(uint16_t)) /* 16 KB */
#define IWM_OTP_LOW_IMAGE_SIZE_FAMILY_8000    (32 * 512 * sizeof(uint16_t)) /* 32 KB */
#define IWM_OTP_LOW_IMAGE_SIZE_FAMILY_9000    IWM_OTP_LOW_IMAGE_SIZE_FAMILY_8000


/**
 * enum iwl_nvm_type - nvm formats
 * @IWM_NVM: the regular format
 * @IWM_NVM_EXT: extended NVM format
 * @IWM_NVM_SDP: NVM format used by 3168 series
 */
enum iwm_nvm_type {
    IWM_NVM,
    IWM_NVM_EXT,
    IWM_NVM_SDP,
};

/**
 * struct iwm_cfg
 * @name: Official name of the device
 * @fw_name: Firmware filename.
 * @host_interrupt_operation_mode: device needs host interrupt operation
 *      mode set
 * @nvm_hw_section_num: the ID of the HW NVM section
 * @apmg_wake_up_wa: should the MAC access REQ be asserted when a command
 *      is in flight. This is due to a HW bug in 7260, 3160 and 7265.
 * @nvm_type: see &enum iwl_nvm_type
 */
struct iwm_cfg {
    const char *name;
    const char *fw_name;
    uint16_t eeprom_size;
    enum iwm_device_family device_family;
    int host_interrupt_operation_mode;
    int mqrx_supported;
    int integrated;
    uint8_t nvm_hw_section_num;
    int apmg_wake_up_wa;
    enum iwm_nvm_type nvm_type;
};

/*
 * This list declares the config structures for all devices.
 */
extern const struct iwm_cfg iwm7260_cfg;
extern const struct iwm_cfg iwm3160_cfg;
extern const struct iwm_cfg iwm3165_cfg;
extern const struct iwm_cfg iwm3168_cfg;
extern const struct iwm_cfg iwm7265_cfg;
extern const struct iwm_cfg iwm7265d_cfg;
extern const struct iwm_cfg iwm8260_cfg;
extern const struct iwm_cfg iwm8265_cfg;
extern const struct iwm_cfg iwm9560_cfg;
extern const struct iwm_cfg iwm9260_cfg;

#endif /* devices_hpp */

//
//  fw.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//
#ifndef CUSTOM_HEADER
#include "itlwm.hpp"
#else
#include "OpenWifi.hpp"
#endif
#include "FwData.h"
#include "kernel.h"

int itlwm::
iwm_is_mimo_ht_plcp(uint8_t ht_plcp)
{
    return (ht_plcp != IWM_RATE_HT_SISO_MCS_INV_PLCP &&
            (ht_plcp & IWM_RATE_HT_MCS_NSS_MSK));
}

int itlwm::
iwm_is_mimo_mcs(int mcs)
{
    int ridx = iwm_mcs2ridx[mcs];
    return iwm_is_mimo_ht_plcp(iwm_rates[ridx].ht_plcp);
    
}

int itlwm::
iwm_store_cscheme(struct iwm_softc *sc, uint8_t *data, size_t dlen)
{
    struct iwm_fw_cscheme_list *l = (struct iwm_fw_cscheme_list *)data;
    
    if (dlen < sizeof(*l) ||
        dlen < sizeof(l->size) + l->size * sizeof(*l->cs))
        return EINVAL;
    
    /* we don't actually store anything for now, always use s/w crypto */
    
    return 0;
}

int itlwm::
iwm_firmware_store_section(struct iwm_softc *sc, enum iwm_ucode_type type,
                           uint8_t *data, size_t dlen)
{
    struct iwm_fw_img *fws;
    struct iwm_fw_desc *fwone;
    
    if (type >= IWM_UCODE_TYPE_MAX)
        return EINVAL;
    if (dlen < sizeof(uint32_t))
        return EINVAL;
    
    fws = &sc->sc_fw.img[type];
    if (fws->fw_count >= IWM_UCODE_SECTION_MAX)
        return EINVAL;
    
    fwone = &fws->sec[fws->fw_count];
    
    /* first 32bit are device load offset */
    memcpy(&fwone->offset, data, sizeof(uint32_t));
    
    /* rest is data */
    fwone->data = data + sizeof(uint32_t);
    fwone->len = dlen - sizeof(uint32_t);
    
    fws->fw_count++;
    
    return 0;
}

#define IWM_DEFAULT_SCAN_CHANNELS 40

struct iwm_tlv_calib_data {
    uint32_t ucode_type;
    struct iwm_tlv_calib_ctrl calib;
} __packed;

int itlwm::
iwm_set_default_calib(struct iwm_softc *sc, const void *data)
{
    const struct iwm_tlv_calib_data *def_calib = (const struct iwm_tlv_calib_data *)data;
    uint32_t ucode_type = le32toh(def_calib->ucode_type);
    
    if (ucode_type >= IWM_UCODE_TYPE_MAX)
        return EINVAL;
    
    sc->sc_default_calib[ucode_type].flow_trigger =
    def_calib->calib.flow_trigger;
    sc->sc_default_calib[ucode_type].event_trigger =
    def_calib->calib.event_trigger;
    
    return 0;
}

void itlwm::
iwm_fw_info_free(struct iwm_fw_info *fw)
{
    free(fw->fw_rawdata, M_DEVBUF, fw->fw_rawsize);
    fw->fw_rawdata = NULL;
    fw->fw_rawsize = 0;
    /* don't touch fw->fw_status */
    memset(fw->img, 0, sizeof(fw->img));
}

void itlwm::
onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context)
{
    XYLog("onLoadFW callback ret=0x%08x length=%d", result, resourceDataLength);
    ResourceCallbackContext *resourceContxt = (ResourceCallbackContext*)context;
    IOLockLock(resourceContxt->context->fwLoadLock);
    if (resourceDataLength > 0) {
        XYLog("onLoadFW return success");
        resourceContxt->resource = OSData::withBytes(resourceData, resourceDataLength);
    }
    IOLockUnlock(resourceContxt->context->fwLoadLock);
    IOLockWakeup(resourceContxt->context->fwLoadLock, resourceContxt->context, false);
    XYLog("onLoadFW wakeupOn");
}

static int
iwm_set_ucode_capabilities(struct iwm_softc *sc, const uint8_t *data,
                           struct iwm_ucode_capabilities *capa)
{
    const struct iwm_ucode_capa *ucode_capa = (const struct iwm_ucode_capa *)data;
    uint32_t api_index = le32toh(ucode_capa->api_index);
    uint32_t api_flags = le32toh(ucode_capa->api_capa);
    int i;
    
    if (api_index >= howmany(IWM_NUM_UCODE_TLV_CAPA, 32)) {
        XYLog("capa flags index %d larger than supported by driver\n",
              api_index);
        /* don't return an error so we can load FW that has more bits */
        return 0;
    }
    
    for (i = 0; i < 32; i++) {
        if (api_flags & (1U << i))
            setbit(capa->enabled_capa, i + 32 * api_index);
    }
    
    return 0;
}

static int
iwm_set_ucode_api_flags(struct iwm_softc *sc, const uint8_t *data,
                        struct iwm_ucode_capabilities *capa)
{
    const struct iwm_ucode_api *ucode_api = (const struct iwm_ucode_api *)data;
    uint32_t api_index = le32toh(ucode_api->api_index);
    uint32_t api_flags = le32toh(ucode_api->api_flags);
    int i;
    
    if (api_index >= howmany(IWM_NUM_UCODE_TLV_API, 32)) {
        XYLog("api flags index %d larger than supported by driver\n",
              api_index);
        /* don't return an error so we can load FW that has more bits */
        return 0;
    }
    
    for (i = 0; i < 32; i++) {
        if (api_flags & (1U << i))
            setbit(capa->enabled_api, i + 32 * api_index);
    }
    
    return 0;
}

int itlwm::
iwm_read_firmware(struct iwm_softc *sc, enum iwm_ucode_type ucode_type)
{
    struct iwm_fw_info *fw = &sc->sc_fw;
    struct iwm_tlv_ucode_header *uhdr;
    struct iwm_ucode_tlv *tlv;
    struct iwm_ucode_capabilities *capa = &sc->sc_fw.ucode_capa;
    uint32_t usniffer_img;
    uint32_t paging_mem_size;
    uint32_t tlv_type;
    uint8_t *data;
    int err;
    size_t len;
    size_t tlv_len;
    void *tlv_data;
    OSData *fwData = NULL;
    
    if (fw->fw_status == IWM_FW_STATUS_DONE &&
        ucode_type != IWM_UCODE_INIT)
        return 0;
    
    while (fw->fw_status == IWM_FW_STATUS_INPROGRESS)
        tsleep_nsec(&sc->sc_fw, 0, "iwmfwp", INFSLP);
    fw->fw_status = IWM_FW_STATUS_INPROGRESS;
    
    if (fw->fw_rawdata != NULL)
        iwm_fw_info_free(fw);
    
    //TODO
    //    err = loadfirmware(sc->sc_fwname,
    //        (u_char **)&fw->fw_rawdata, &fw->fw_rawsize);
    IOLockLock(fwLoadLock);
    ResourceCallbackContext context =
    {
        .context = this,
        .resource = NULL
    };
    IOReturn ret = OSKextRequestResource(OSKextGetCurrentIdentifier(), sc->sc_fwname, onLoadFW, &context, NULL);
    IOLockSleep(fwLoadLock, this, 0);
    IOLockUnlock(fwLoadLock);
    if (context.resource == NULL) {
        XYLog("%s resource load fail.\n", sc->sc_fwname);
        goto out;
    }
    fw->fw_rawdata = (u_char*)context.resource->getBytesNoCopy();
    fw->fw_rawsize = context.resource->getLength();
    //    fwData = getFWDescByName(sc->sc_fwname);
    //    if (fwData == NULL) {
    //        XYLog("%s resource load fail.\n", sc->sc_fwname);
    //        goto out;
    //    }
    //    fw->fw_rawdata = (u_char*)fwData->getBytesNoCopy();
    //    fw->fw_rawsize = fwData->getLength();
    XYLog("load firmware done\n");
    capa->flags = 0;
    capa->max_probe_length = IWM_DEFAULT_MAX_PROBE_LENGTH;
    capa->n_scan_channels = IWM_DEFAULT_SCAN_CHANNELS;
    memset(capa->enabled_capa, 0, sizeof(capa->enabled_capa));
    memset(capa->enabled_api, 0, sizeof(capa->enabled_api));
    memset(sc->sc_fw_mcc, 0, sizeof(sc->sc_fw_mcc));
    
    /*
     * Parse firmware contents
     */
    
    uhdr = (struct iwm_tlv_ucode_header *)fw->fw_rawdata;
    if (*(uint32_t *)fw->fw_rawdata != 0
        || le32toh(uhdr->magic) != IWM_TLV_UCODE_MAGIC) {
        XYLog("%s: invalid firmware %s\n",
              DEVNAME(sc), sc->sc_fwname);
        err = EINVAL;
        goto out;
    }
    
    snprintf(sc->sc_fwver, sizeof(sc->sc_fwver), "%d.%d (API ver %d)",
             IWM_UCODE_MAJOR(le32toh(uhdr->ver)),
             IWM_UCODE_MINOR(le32toh(uhdr->ver)),
             IWM_UCODE_API(le32toh(uhdr->ver)));
    data = uhdr->data;
    len = fw->fw_rawsize - sizeof(*uhdr);
    
    while (len >= sizeof(*tlv)) {
        len -= sizeof(*tlv);
        
        tlv = (iwm_ucode_tlv *)data;
        tlv_len = le32toh(tlv->length);
        tlv_type = le32toh(tlv->type);
        tlv_data = tlv->data;
        
        if (len < tlv_len) {
            XYLog("%s: firmware too short: %zu bytes\n",
                  DEVNAME(sc), len);
            err = EINVAL;
            goto parse_out;
        }
        
        len -= _ALIGN(tlv_len, 4);
        data += sizeof(*tlv) + _ALIGN(tlv_len, 4);
        
        switch (tlv_type) {
            case IWM_UCODE_TLV_PROBE_MAX_LEN:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                capa->max_probe_length =
                le32_to_cpup((const uint32_t *)tlv_data);
                break;
            case IWM_UCODE_TLV_PAN:
                if (tlv_len) {
                    err = EINVAL;
                    goto parse_out;
                }
                capa->flags |= IWM_UCODE_TLV_FLAGS_PAN;
                break;
            case IWM_UCODE_TLV_FLAGS:
                if (tlv_len < sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                /*
                 * Apparently there can be many flags, but Linux driver
                 * parses only the first one, and so do we.
                 *
                 * XXX: why does this override IWM_UCODE_TLV_PAN?
                 * Intentional or a bug?  Observations from
                 * current firmware file:
                 *  1) TLV_PAN is parsed first
                 *  2) TLV_FLAGS contains TLV_FLAGS_PAN
                 * ==> this resets TLV_PAN to itself... hnnnk
                 */
                capa->flags = le32_to_cpup((const uint32_t *)tlv_data);
                break;
            case IWM_UCODE_TLV_CSCHEME:
                err = iwm_store_cscheme(sc, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_NUM_OF_CPU: {
                uint32_t num_of_cpus;
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                num_of_cpus = le32toh(*(uint32_t *)tlv_data);
                if (num_of_cpus == 2) {
                    fw->img[IWM_UCODE_REGULAR].is_dual_cpus =
                    TRUE;
                    fw->img[IWM_UCODE_INIT].is_dual_cpus =
                    TRUE;
                    fw->img[IWM_UCODE_WOWLAN].is_dual_cpus =
                    TRUE;
                } else if ((num_of_cpus > 2) || (num_of_cpus < 1)) {
                    XYLog("%s: Driver supports only 1 or 2 CPUs\n",
                          __func__);
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            }
            case IWM_UCODE_TLV_SEC_RT:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_REGULAR, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_SEC_INIT:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_INIT, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_SEC_WOWLAN:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_WOWLAN, (uint8_t*)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_DEF_CALIB:
                if (tlv_len != sizeof(struct iwm_tlv_calib_data)) {
                    err = EINVAL;
                    goto parse_out;
                }
                err = iwm_set_default_calib(sc, tlv_data);
                if (err)
                    goto parse_out;
                break;
            case IWM_UCODE_TLV_PHY_SKU:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_fw.phy_config =
                le32_to_cpup((const uint32_t *)tlv_data);
                sc->sc_fw.valid_tx_ant = (sc->sc_fw.phy_config &
                                          IWM_FW_PHY_CFG_TX_CHAIN) >>
                IWM_FW_PHY_CFG_TX_CHAIN_POS;
                sc->sc_fw.valid_rx_ant = (sc->sc_fw.phy_config &
                                          IWM_FW_PHY_CFG_RX_CHAIN) >>
                IWM_FW_PHY_CFG_RX_CHAIN_POS;
                break;
                
            case IWM_UCODE_TLV_API_CHANGES_SET: {
                struct iwm_ucode_api *api;
                if (tlv_len != sizeof(*api)) {
                    err = EINVAL;
                    goto parse_out;
                }
                if (iwm_set_ucode_api_flags(sc, (const uint8_t*)tlv_data, capa)) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            }
                
            case IWM_UCODE_TLV_ENABLED_CAPABILITIES: {
                if (tlv_len != sizeof(iwm_ucode_api)) {
                    XYLog("%s tlv_len != sizeof(*capa)\n", __FUNCTION__);
                    err = EINVAL;
                    goto parse_out;
                }
                if (iwm_set_ucode_capabilities(sc, (const uint8_t*)tlv_data, capa)) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            }
                
            case 48:
            case IWM_UCODE_TLV_SDIO_ADMA_ADDR:
            case IWM_UCODE_TLV_FW_GSCAN_CAPA:
                /* ignore, not used by current driver */
                break;
                
            case IWM_UCODE_TLV_SEC_RT_USNIFFER:
                err = iwm_firmware_store_section(sc,
                                                 IWM_UCODE_REGULAR_USNIFFER, (uint8_t*)tlv_data,
                                                 tlv_len);
                if (err)
                    goto parse_out;
                break;
                
            case IWM_UCODE_TLV_PAGING:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                paging_mem_size = le32_to_cpup((const uint32_t *)tlv_data);
                
                XYLog("%s: Paging: paging enabled (size = %u bytes)\n",
                      __func__, paging_mem_size);
                if (paging_mem_size > IWM_MAX_PAGING_IMAGE_SIZE) {
                    XYLog("%s: Paging: driver supports up to %u bytes for paging image\n",
                          __func__, IWM_MAX_PAGING_IMAGE_SIZE);
                    err = EINVAL;
                    goto out;
                }
                if (paging_mem_size & (IWM_FW_PAGING_SIZE - 1)) {
                    XYLog("%s: Paging: image isn't multiple %u\n",
                          __func__, IWM_FW_PAGING_SIZE);
                    err = EINVAL;
                    goto out;
                }
                
                sc->sc_fw.img[IWM_UCODE_REGULAR].paging_mem_size =
                paging_mem_size;
                usniffer_img = IWM_UCODE_REGULAR_USNIFFER;
                sc->sc_fw.img[usniffer_img].paging_mem_size =
                paging_mem_size;
                break;
                
            case IWM_UCODE_TLV_N_SCAN_CHANNELS:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                capa->n_scan_channels =
                le32_to_cpup((const uint32_t *)tlv_data);
                break;
                
            case IWM_UCODE_TLV_FW_VERSION:
                if (tlv_len != sizeof(uint32_t) * 3) {
                    err = EINVAL;
                    goto parse_out;
                }
                snprintf(sc->sc_fwver, sizeof(sc->sc_fwver),
                         "%u.%u.%u",
                         le32toh(((const uint32_t *)tlv_data)[0]),
                         le32toh(((const uint32_t *)tlv_data)[1]),
                         le32toh(((const uint32_t *)tlv_data)[2]));
                break;
                
            case IWM_UCODE_TLV_FW_MEM_SEG:
                break;
                
            default:
                XYLog("%s: unknown firmware section %d\n",
                      __func__, tlv_type);
                break;
        }
    }
    
    _KASSERT(err == 0);
    
parse_out:
    if (err) {
        XYLog("%s: firmware parse error %d, "
              "section type %d\n", DEVNAME(sc), err, tlv_type);
    }
    
out:
    if (err) {
        fw->fw_status = IWM_FW_STATUS_NONE;
        if (fw->fw_rawdata != NULL)
            iwm_fw_info_free(fw);
    } else
        fw->fw_status = IWM_FW_STATUS_DONE;
    wakeupOn(&sc->sc_fw);
    
    return err;
}

int itlwm::
iwm_post_alive(struct iwm_softc *sc)
{
    int nwords;
    int err, chnl;
    uint32_t base;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    base = iwm_read_prph(sc, IWM_SCD_SRAM_BASE_ADDR);
    
    iwm_ict_reset(sc);
    
    /* Clear TX scheduler state in SRAM. */
    nwords = (IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND -
              IWM_SCD_CONTEXT_MEM_LOWER_BOUND)
    / sizeof(uint32_t);
    err = iwm_write_mem(sc,
                        sc->scd_base_addr + IWM_SCD_CONTEXT_MEM_LOWER_BOUND,
                        NULL, nwords);
    if (err)
        goto out;
    
    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwm_write_prph(sc, IWM_SCD_DRAM_BASE_ADDR, sc->sched_dma.paddr >> 10);
    
    iwm_write_prph(sc, IWM_SCD_CHAINEXT_EN, 0);
    
    /* enable command channel */
    err = iwm_enable_txq(sc, 0 /* unused */, IWM_CMD_QUEUE, 7);
    if (err)
        goto out;
    
    /* Activate TX scheduler. */
    iwm_write_prph(sc, IWM_SCD_TXFACT, 0xff);
    
    /* Enable DMA channels. */
    for (chnl = 0; chnl < IWM_FH_TCSR_CHNL_NUM; chnl++) {
        IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(chnl),
                  IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
                  IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE);
    }
    
    IWM_SETBITS(sc, IWM_FH_TX_CHICKEN_BITS_REG,
                IWM_FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN);
    
    /* Enable L1-Active */
    if (sc->sc_device_family != IWM_DEVICE_FAMILY_8000)
        iwm_clear_bits_prph(sc, IWM_APMG_PCIDEV_STT_REG,
                            IWM_APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
    
out:
    iwm_nic_unlock(sc);
    return err;
}

uint8_t itlwm::
iwm_get_valid_tx_ant(struct iwm_softc *sc)
{
    return sc->nvm_data && sc->nvm_data->valid_tx_ant ?
    sc->sc_fw.valid_tx_ant & sc->nvm_data->valid_tx_ant :
    sc->sc_fw.valid_tx_ant;
}

uint8_t itlwm::
iwm_fw_valid_rx_ant(struct iwm_softc *sc)
{
    return sc->nvm_data && sc->nvm_data->valid_rx_ant ?
    sc->sc_fw.valid_rx_ant & sc->nvm_data->valid_rx_ant :
    sc->sc_fw.valid_rx_ant;
}

int itlwm::
iwm_pcie_load_section(struct iwm_softc *sc, uint8_t section_num,
    const struct iwm_fw_desc *section)
{
    struct iwm_dma_info *dma = &sc->fw_dma;
    uint8_t *v_addr;
    bus_addr_t p_addr;
    uint32_t offset, chunk_sz = MIN(IWM_FH_MEM_TB_MAX_LENGTH, section->len);
    int ret = 0;

    XYLog("%s: [%d] uCode section being loaded...\n",
            __func__, section_num);

    v_addr = (uint8_t*)dma->vaddr;
    p_addr = dma->paddr;

    for (offset = 0; offset < section->len; offset += chunk_sz) {
        uint32_t copy_size, dst_addr;
        int extended_addr = FALSE;

        copy_size = MIN(chunk_sz, section->len - offset);
        dst_addr = section->offset + offset;

        if (dst_addr >= IWM_FW_MEM_EXTENDED_START &&
            dst_addr <= IWM_FW_MEM_EXTENDED_END)
            extended_addr = TRUE;

        if (extended_addr)
            iwm_set_bits_prph(sc, IWM_LMPM_CHICK,
                      IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE);

        memcpy(v_addr, (const uint8_t *)section->data + offset,
            copy_size);
//        bus_dmamap_sync(dma->tag, dma->map, BUS_DMASYNC_PREWRITE);
        ret = iwm_pcie_load_firmware_chunk(sc, dst_addr, p_addr,
                           copy_size);

        if (extended_addr)
            iwm_clear_bits_prph(sc, IWM_LMPM_CHICK,
                        IWM_LMPM_CHICK_EXTENDED_ADDR_SPACE);

        if (ret) {
            XYLog("%s: Could not load the [%d] uCode section\n",
                __func__, section_num);
            break;
        }
    }

    return ret;
}

/*
 * ucode
 */
int itlwm::
iwm_pcie_load_firmware_chunk(struct iwm_softc *sc, uint32_t dst_addr,
                 bus_addr_t phy_addr, uint32_t byte_cnt)
{
    struct timespec ts;
    sc->sc_fw_chunk_done = 0;

    if (!iwm_nic_lock(sc))
        return EBUSY;

    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
        IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);

    IWM_WRITE(sc, IWM_FH_SRVC_CHNL_SRAM_ADDR_REG(IWM_FH_SRVC_CHNL),
        dst_addr);

    IWM_WRITE(sc, IWM_FH_TFDIB_CTRL0_REG(IWM_FH_SRVC_CHNL),
        phy_addr & IWM_FH_MEM_TFDIB_DRAM_ADDR_LSB_MSK);

    IWM_WRITE(sc, IWM_FH_TFDIB_CTRL1_REG(IWM_FH_SRVC_CHNL),
        (iwm_get_dma_hi_addr(phy_addr)
         << IWM_FH_MEM_TFDIB_REG1_ADDR_BITSHIFT) | byte_cnt);

    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_BUF_STS_REG(IWM_FH_SRVC_CHNL),
        1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM |
        1 << IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX |
        IWM_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID);

    IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(IWM_FH_SRVC_CHNL),
        IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE    |
        IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE |
        IWM_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD);

    iwm_nic_unlock(sc);

    /* wait up to 5s for this segment to load */
    ts.tv_nsec = hz * 5;
    msleep(&sc->sc_fw, sc->sc_mtx.mtx_lock, 0, "iwmfw", &ts);

    if (!sc->sc_fw_chunk_done) {
        XYLog("fw chunk addr 0x%x len %d failed to load\n",
            dst_addr, byte_cnt);
        return ETIMEDOUT;
    }

    return 0;
}

int itlwm::
iwm_pcie_load_cpu_sections_8000(struct iwm_softc *sc,
    const struct iwm_fw_img *image, int cpu, int *first_ucode_section)
{
    int shift_param;
    int i, ret = 0, sec_num = 0x1;
    uint32_t val, last_read_idx = 0;

    if (cpu == 1) {
        shift_param = 0;
        *first_ucode_section = 0;
    } else {
        shift_param = 16;
        (*first_ucode_section)++;
    }

    for (i = *first_ucode_section; i < IWM_UCODE_SECTION_MAX; i++) {
        last_read_idx = i;

        /*
         * CPU1_CPU2_SEPARATOR_SECTION delimiter - separate between
         * CPU1 to CPU2.
         * PAGING_SEPARATOR_SECTION delimiter - separate between
         * CPU2 non paged to CPU2 paging sec.
         */
        if (!image->sec[i].data ||
            image->sec[i].offset == IWM_CPU1_CPU2_SEPARATOR_SECTION ||
            image->sec[i].offset == IWM_PAGING_SEPARATOR_SECTION) {
            XYLog("Break since Data not valid or Empty section, sec = %d\n",
                    i);
            break;
        }
        ret = iwm_pcie_load_section(sc, i, &image->sec[i]);
        if (ret)
            return ret;

        /* Notify the ucode of the loaded section number and status */
        if (iwm_nic_lock(sc)) {
            val = IWM_READ(sc, IWM_FH_UCODE_LOAD_STATUS);
            val = val | (sec_num << shift_param);
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, val);
            sec_num = (sec_num << 1) | 0x1;
            iwm_nic_unlock(sc);
        }
    }

    *first_ucode_section = last_read_idx;

    iwm_enable_interrupts(sc);

    if (iwm_nic_lock(sc)) {
        if (cpu == 1)
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, 0xFFFF);
        else
            IWM_WRITE(sc, IWM_FH_UCODE_LOAD_STATUS, 0xFFFFFFFF);
        iwm_nic_unlock(sc);
    }

    return 0;
}

int itlwm::
iwm_pcie_load_cpu_sections(struct iwm_softc *sc,
    const struct iwm_fw_img *image, int cpu, int *first_ucode_section)
{
    int shift_param;
    int i, ret = 0;
    uint32_t last_read_idx = 0;

    if (cpu == 1) {
        shift_param = 0;
        *first_ucode_section = 0;
    } else {
        shift_param = 16;
        (*first_ucode_section)++;
    }

    for (i = *first_ucode_section; i < IWM_UCODE_SECTION_MAX; i++) {
        last_read_idx = i;

        /*
         * CPU1_CPU2_SEPARATOR_SECTION delimiter - separate between
         * CPU1 to CPU2.
         * PAGING_SEPARATOR_SECTION delimiter - separate between
         * CPU2 non paged to CPU2 paging sec.
         */
        if (!image->sec[i].data ||
            image->sec[i].offset == IWM_CPU1_CPU2_SEPARATOR_SECTION ||
            image->sec[i].offset == IWM_PAGING_SEPARATOR_SECTION) {
            XYLog("Break since Data not valid or Empty section, sec = %d\n",
                     i);
            break;
        }

        ret = iwm_pcie_load_section(sc, i, &image->sec[i]);
        if (ret)
            return ret;
    }

    *first_ucode_section = last_read_idx;

    return 0;

}

int itlwm::
iwm_pcie_load_given_ucode(struct iwm_softc *sc, const struct iwm_fw_img *image)
{
    int ret = 0;
    int first_ucode_section;

    XYLog("working with %s CPU\n",
             image->is_dual_cpus ? "Dual" : "Single");

    /* load to FW the binary non secured sections of CPU1 */
    ret = iwm_pcie_load_cpu_sections(sc, image, 1, &first_ucode_section);
    if (ret)
        return ret;

    if (image->is_dual_cpus) {
        /* set CPU2 header address */
        if (iwm_nic_lock(sc)) {
            iwm_write_prph(sc,
                       IWM_LMPM_SECURE_UCODE_LOAD_CPU2_HDR_ADDR,
                       IWM_LMPM_SECURE_CPU2_HDR_MEM_SPACE);
            iwm_nic_unlock(sc);
        }

        /* load to FW the binary sections of CPU2 */
        ret = iwm_pcie_load_cpu_sections(sc, image, 2,
                         &first_ucode_section);
        if (ret)
            return ret;
    }

    iwm_enable_interrupts(sc);

    /* release CPU reset */
    IWM_WRITE(sc, IWM_CSR_RESET, 0);

    return 0;
}

int itlwm::
iwm_pcie_load_given_ucode_8000(struct iwm_softc *sc,
    const struct iwm_fw_img *image)
{
    int ret = 0;
    int first_ucode_section;

    XYLog("working with %s CPU\n",
            image->is_dual_cpus ? "Dual" : "Single");

    /* configure the ucode to be ready to get the secured image */
    /* release CPU reset */
    if (iwm_nic_lock(sc)) {
        iwm_write_prph(sc, IWM_RELEASE_CPU_RESET,
            IWM_RELEASE_CPU_RESET_BIT);
        iwm_nic_unlock(sc);
    }

    /* load to FW the binary Secured sections of CPU1 */
    ret = iwm_pcie_load_cpu_sections_8000(sc, image, 1,
        &first_ucode_section);
    if (ret)
        return ret;

    /* load to FW the binary sections of CPU2 */
    return iwm_pcie_load_cpu_sections_8000(sc, image, 2,
        &first_ucode_section);
}

/* XXX Get rid of this definition */
static inline void
iwm_enable_fw_load_int(struct iwm_softc *sc)
{
    XYLog("Enabling FW load interrupt\n");
    sc->sc_intmask = IWM_CSR_INT_BIT_FH_TX;
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}

int itlwm::
iwm_start_fw(struct iwm_softc *sc, const struct iwm_fw_img *fw)
{
    int ret;

    /* This may fail if AMT took ownership of the device */
    if (iwm_prepare_card_hw(sc)) {
        XYLog("%s: Exit HW not ready\n", __func__);
        ret = EIO;
        goto out;
    }

    IWM_WRITE(sc, IWM_CSR_INT, 0xFFFFFFFF);

    iwm_disable_interrupts(sc);
    
    /* make sure rfkill handshake bits are cleared */
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
    IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR,
        IWM_CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
    
    /* clear (again), then enable host interrupts */
    IWM_WRITE(sc, IWM_CSR_INT, 0xFFFFFFFF);
    
    ret = iwm_nic_init(sc);
    if (ret) {
        XYLog("%s: Unable to init nic\n", __func__);
        goto out;
    }
    
    /*
     * Now, we load the firmware and don't want to be interrupted, even
     * by the RF-Kill interrupt (hence mask all the interrupt besides the
     * FH_TX interrupt which is needed to load the firmware). If the
     * RF-Kill switch is toggled, we will find out after having loaded
     * the firmware and return the proper value to the caller.
     */
    iwm_enable_fw_load_int(sc);
    
    /* really make sure rfkill handshake bits are cleared */
        /* maybe we should write a few times more?  just to make sure */
        IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);
        IWM_WRITE(sc, IWM_CSR_UCODE_DRV_GP1_CLR, IWM_CSR_UCODE_SW_BIT_RFKILL);

        /* Load the given image to the HW */
        if (sc->cfg->device_family >= IWM_DEVICE_FAMILY_8000)
            ret = iwm_pcie_load_given_ucode_8000(sc, fw);
        else
            ret = iwm_pcie_load_given_ucode(sc, fw);

        /* XXX re-check RF-Kill state */

    out:
        return ret;
}

int itlwm::
iwm_send_tx_ant_cfg(struct iwm_softc *sc, uint8_t valid_tx_ant)
{
    XYLog("%s\n", __func__);
    struct iwm_tx_ant_cfg_cmd tx_ant_cmd = {
        .valid = htole32(valid_tx_ant),
    };
    
    return iwm_send_cmd_pdu(sc, IWM_TX_ANT_CONFIGURATION_CMD,
                            0, sizeof(tx_ant_cmd), &tx_ant_cmd);
}

struct iwm_alive_data {
    int valid;
    uint32_t scd_base_addr;
};

#define IWM_UCODE_ALIVE_TIMEOUT    hz
#define IWM_UCODE_CALIB_TIMEOUT    (2*hz)

static int
iwm_alive_fn(struct iwm_softc *sc, struct iwm_rx_packet *pkt, void *data)
{
    struct iwm_alive_data *alive_data = (struct iwm_alive_data *)data;
    struct iwm_alive_resp_v3 *palive3;
    struct iwm_alive_resp *palive;
    struct iwm_umac_alive *umac;
    struct iwm_lmac_alive *lmac1;
    struct iwm_lmac_alive *lmac2 = NULL;
    uint16_t status;

    if (iwm_rx_packet_payload_len(pkt) == sizeof(*palive)) {
        palive = (struct iwm_alive_resp *)pkt->data;
        umac = &palive->umac_data;
        lmac1 = &palive->lmac_data[0];
        lmac2 = &palive->lmac_data[1];
        status = le16toh(palive->status);
    } else {
        palive3 = (struct iwm_alive_resp_v3 *)pkt->data;
        umac = &palive3->umac_data;
        lmac1 = &palive3->lmac_data;
        status = le16toh(palive3->status);
    }

    sc->error_event_table[0] = le32toh(lmac1->error_event_table_ptr);
    if (lmac2)
        sc->error_event_table[1] =
            le32toh(lmac2->error_event_table_ptr);
    sc->log_event_table = le32toh(lmac1->log_event_table_ptr);
    sc->umac_error_event_table = le32toh(umac->error_info_addr);
    alive_data->scd_base_addr = le32toh(lmac1->scd_base_ptr);
    alive_data->valid = status == IWM_ALIVE_STATUS_OK;
    if (sc->umac_error_event_table)
        sc->support_umac_log = TRUE;

    XYLog("Alive ucode status 0x%04x revision 0x%01X 0x%01X\n",
            status, lmac1->ver_type, lmac1->ver_subtype);

    if (lmac2)
        XYLog("Alive ucode CDB\n");

    XYLog("UMAC version: Major - 0x%x, Minor - 0x%x\n",
            le32toh(umac->umac_major),
            le32toh(umac->umac_minor));

    return TRUE;
}

static int
iwm_wait_phy_db_entry(struct iwm_softc *sc,
                      struct iwm_rx_packet *pkt, void *data)
{
    struct iwm_phy_db *phy_db = (struct iwm_phy_db *)data;
    itlwm *that = container_of(sc, itlwm, com);
    
    if (pkt->hdr.code != IWM_CALIB_RES_NOTIF_PHY_DB) {
        if(pkt->hdr.code != IWM_INIT_COMPLETE_NOTIF) {
            XYLog("%s: Unexpected cmd: %d\n",
                  __func__, pkt->hdr.code);
        }
        return TRUE;
    }
    
    if (that->iwm_phy_db_set_section(phy_db, pkt)) {
        XYLog("%s: iwm_phy_db_set_section failed\n", __func__);
    }
    
    return FALSE;
}

int itlwm::
iwm_trans_pcie_fw_alive(struct iwm_softc *sc, uint32_t scd_base_addr)
{
    int error, chnl;

    int clear_dwords = (IWM_SCD_TRANS_TBL_MEM_UPPER_BOUND -
        IWM_SCD_CONTEXT_MEM_LOWER_BOUND) / sizeof(uint32_t);

    if (!iwm_nic_lock(sc))
        return EBUSY;

    iwm_ict_reset(sc);

    sc->scd_base_addr = iwm_read_prph(sc, IWM_SCD_SRAM_BASE_ADDR);
    if (scd_base_addr != 0 &&
        scd_base_addr != sc->scd_base_addr) {
        XYLog("%s: sched addr mismatch: alive: 0x%x prph: 0x%x\n",
            __func__, sc->scd_base_addr, scd_base_addr);
    }

    iwm_nic_unlock(sc);

    /* reset context data, TX status and translation data */
    error = iwm_write_mem(sc,
        sc->scd_base_addr + IWM_SCD_CONTEXT_MEM_LOWER_BOUND,
        NULL, clear_dwords);
    if (error)
        return EBUSY;

    if (!iwm_nic_lock(sc))
        return EBUSY;

    /* Set physical address of TX scheduler rings (1KB aligned). */
    iwm_write_prph(sc, IWM_SCD_DRAM_BASE_ADDR, sc->sched_dma.paddr >> 10);

    iwm_write_prph(sc, IWM_SCD_CHAINEXT_EN, 0);

    iwm_nic_unlock(sc);

    /* enable command channel */
    error = iwm_enable_txq(sc, 0 /* unused */, IWM_CMD_QUEUE, 7);
    if (error)
        return error;

    if (!iwm_nic_lock(sc))
        return EBUSY;

    iwm_write_prph(sc, IWM_SCD_TXFACT, 0xff);

    /* Enable DMA channels. */
    for (chnl = 0; chnl < IWM_FH_TCSR_CHNL_NUM; chnl++) {
        IWM_WRITE(sc, IWM_FH_TCSR_CHNL_TX_CONFIG_REG(chnl),
            IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
            IWM_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE);
    }

    IWM_SETBITS(sc, IWM_FH_TX_CHICKEN_BITS_REG,
        IWM_FH_TX_CHICKEN_BITS_SCD_AUTO_RETRY_EN);

    iwm_nic_unlock(sc);

    /* Enable L1-Active */
    if (sc->cfg->device_family < IWM_DEVICE_FAMILY_8000) {
        iwm_clear_bits_prph(sc, IWM_APMG_PCIDEV_STT_REG,
            IWM_APMG_PCIDEV_STT_VAL_L1_ACT_DIS);
    }

    return error;
}

int itlwm::
iwm_load_ucode_wait_alive(struct iwm_softc *sc,
                          enum iwm_ucode_type ucode_type)
{
    XYLog("%s\n", __func__);
    struct iwm_notification_wait alive_wait;
    struct iwm_alive_data alive_data;
    const struct iwm_fw_img *fw;
    enum iwm_ucode_type old_type = sc->cur_ucode;
    int error;
    static const uint16_t alive_cmd[] = { IWM_ALIVE };
    
    fw = &sc->sc_fw.img[ucode_type];
    sc->cur_ucode = ucode_type;
    sc->ucode_loaded = FALSE;

    memset(&alive_data, 0, sizeof(alive_data));
    iwm_init_notification_wait(sc->sc_notif_wait, &alive_wait,
                   alive_cmd, nitems(alive_cmd),
                   iwm_alive_fn, &alive_data);

    error = iwm_start_fw(sc, fw);
    if (error) {
        XYLog("iwm_start_fw: failed %d\n", error);
        sc->cur_ucode = old_type;
        iwm_remove_notification(sc->sc_notif_wait, &alive_wait);
        return error;
    }
    
    /*
     * Some things may run in the background now, but we
     * just wait for the ALIVE notification here.
     */
    IWM_UNLOCK(sc);
    error = iwm_wait_notification(sc->sc_notif_wait, &alive_wait,
                      IWM_UCODE_ALIVE_TIMEOUT);
    IWM_LOCK(sc);
    if (error) {
        if (sc->cfg->device_family >= IWM_DEVICE_FAMILY_8000) {
            uint32_t a = 0x5a5a5a5a, b = 0x5a5a5a5a;
            if (iwm_nic_lock(sc)) {
                a = iwm_read_prph(sc, IWM_SB_CPU_1_STATUS);
                b = iwm_read_prph(sc, IWM_SB_CPU_2_STATUS);
                iwm_nic_unlock(sc);
            }
            XYLog("SecBoot CPU1 Status: 0x%x, CPU2 Status: 0x%x\n",
                a, b);
        }
        sc->cur_ucode = old_type;
        return error;
    }

    if (!alive_data.valid) {
        XYLog("%s: Loaded ucode is not valid\n",
            __func__);
        sc->cur_ucode = old_type;
        return EIO;
    }

    iwm_trans_pcie_fw_alive(sc, alive_data.scd_base_addr);

    /*
     * configure and operate fw paging mechanism.
     * driver configures the paging flow only once, CPU2 paging image
     * included in the IWM_UCODE_INIT image.
     */
    if (fw->paging_mem_size) {
        error = iwm_save_fw_paging(sc, fw);
        if (error) {
            XYLog("%s: failed to save the FW paging image\n",
                __func__);
            return error;
        }

        error = iwm_send_paging_cmd(sc, fw);
        if (error) {
            XYLog("%s: failed to send the paging cmd\n", __func__);
            iwm_free_fw_paging(sc);
            return error;
        }
    }

    if (!error)
        sc->ucode_loaded = TRUE;
    return error;
}

void itlwm::
iwm_free_fw_paging(struct iwm_softc *sc)
{
    int i;

    if (sc->fw_paging_db[0].fw_paging_block.vaddr == NULL)
        return;

    for (i = 0; i < IWM_NUM_OF_FW_PAGING_BLOCKS; i++) {
        iwm_dma_contig_free(&sc->fw_paging_db[i].fw_paging_block);
    }

    memset(sc->fw_paging_db, 0, sizeof(sc->fw_paging_db));
}

int itlwm::
iwm_fill_paging_mem(struct iwm_softc *sc, const struct iwm_fw_img *image)
{
    int sec_idx, idx;
    uint32_t offset = 0;

    /*
     * find where is the paging image start point:
     * if CPU2 exist and it's in paging format, then the image looks like:
     * CPU1 sections (2 or more)
     * CPU1_CPU2_SEPARATOR_SECTION delimiter - separate between CPU1 to CPU2
     * CPU2 sections (not paged)
     * PAGING_SEPARATOR_SECTION delimiter - separate between CPU2
     * non paged to CPU2 paging sec
     * CPU2 paging CSS
     * CPU2 paging image (including instruction and data)
     */
    for (sec_idx = 0; sec_idx < IWM_UCODE_SECTION_MAX; sec_idx++) {
        if (image->sec[sec_idx].offset == IWM_PAGING_SEPARATOR_SECTION) {
            sec_idx++;
            break;
        }
    }

    /*
     * If paging is enabled there should be at least 2 more sections left
     * (one for CSS and one for Paging data)
     */
    if (sec_idx >= nitems(image->sec) - 1) {
        XYLog("Paging: Missing CSS and/or paging sections\n");
        iwm_free_fw_paging(sc);
        return EINVAL;
    }

    /* copy the CSS block to the dram */
    XYLog("Paging: load paging CSS to FW, sec = %d\n",
            sec_idx);

    memcpy(sc->fw_paging_db[0].fw_paging_block.vaddr,
           image->sec[sec_idx].data,
           sc->fw_paging_db[0].fw_paging_size);

    XYLog("Paging: copied %d CSS bytes to first block\n",
            sc->fw_paging_db[0].fw_paging_size);

    sec_idx++;

    /*
     * copy the paging blocks to the dram
     * loop index start from 1 since that CSS block already copied to dram
     * and CSS index is 0.
     * loop stop at num_of_paging_blk since that last block is not full.
     */
    for (idx = 1; idx < sc->num_of_paging_blk; idx++) {
        memcpy(sc->fw_paging_db[idx].fw_paging_block.vaddr,
               (const char *)image->sec[sec_idx].data + offset,
               sc->fw_paging_db[idx].fw_paging_size);

        XYLog("Paging: copied %d paging bytes to block %d\n",
                sc->fw_paging_db[idx].fw_paging_size,
                idx);

        offset += sc->fw_paging_db[idx].fw_paging_size;
    }

    /* copy the last paging block */
    if (sc->num_of_pages_in_last_blk > 0) {
        memcpy(sc->fw_paging_db[idx].fw_paging_block.vaddr,
               (const char *)image->sec[sec_idx].data + offset,
               IWM_FW_PAGING_SIZE * sc->num_of_pages_in_last_blk);

        XYLog("Paging: copied %d pages in the last block %d\n",
                sc->num_of_pages_in_last_blk, idx);
    }

    return 0;
}

int itlwm::
iwm_alloc_fw_paging_mem(struct iwm_softc *sc, const struct iwm_fw_img *image)
{
    int blk_idx = 0;
    int error, num_of_pages;

    if (sc->fw_paging_db[0].fw_paging_block.vaddr != NULL) {
        int i;
        /* Device got reset, and we setup firmware paging again */
//        for (i = 0; i < sc->num_of_paging_blk + 1; i++) {
//            bus_dmamap_sync(sc->sc_dmat,
//                sc->fw_paging_db[i].fw_paging_block.map,
//                BUS_DMASYNC_POSTWRITE | BUS_DMASYNC_POSTREAD);
//        }
        return 0;
    }

    /* ensure IWM_BLOCK_2_EXP_SIZE is power of 2 of IWM_PAGING_BLOCK_SIZE */
        _Static_assert((1 << IWM_BLOCK_2_EXP_SIZE) == IWM_PAGING_BLOCK_SIZE,
        "IWM_BLOCK_2_EXP_SIZE must be power of 2 of IWM_PAGING_BLOCK_SIZE");

    num_of_pages = image->paging_mem_size / IWM_FW_PAGING_SIZE;
    sc->num_of_paging_blk = ((num_of_pages - 1) /
                    IWM_NUM_OF_PAGE_PER_GROUP) + 1;

    sc->num_of_pages_in_last_blk =
        num_of_pages -
        IWM_NUM_OF_PAGE_PER_GROUP * (sc->num_of_paging_blk - 1);

    XYLog("Paging: allocating mem for %d paging blocks, each block holds 8 pages, last block holds %d pages\n",
            sc->num_of_paging_blk,
            sc->num_of_pages_in_last_blk);

    /* allocate block of 4Kbytes for paging CSS */
    error = iwm_dma_contig_alloc(sc->sc_dmat,
        &sc->fw_paging_db[blk_idx].fw_paging_block, NULL, IWM_FW_PAGING_SIZE,
        4096);
    if (error) {
        /* free all the previous pages since we failed */
        iwm_free_fw_paging(sc);
        return ENOMEM;
    }

    sc->fw_paging_db[blk_idx].fw_paging_size = IWM_FW_PAGING_SIZE;

    XYLog("Paging: allocated 4K(CSS) bytes for firmware paging.\n");

    /*
     * allocate blocks in dram.
     * since that CSS allocated in fw_paging_db[0] loop start from index 1
     */
    for (blk_idx = 1; blk_idx < sc->num_of_paging_blk + 1; blk_idx++) {
        /* allocate block of IWM_PAGING_BLOCK_SIZE (32K) */
        /* XXX Use iwm_dma_contig_alloc for allocating */
        error = iwm_dma_contig_alloc(sc->sc_dmat,
             &sc->fw_paging_db[blk_idx].fw_paging_block, NULL,
            IWM_PAGING_BLOCK_SIZE, 4096);
        if (error) {
            /* free all the previous pages since we failed */
            iwm_free_fw_paging(sc);
            return ENOMEM;
        }

        sc->fw_paging_db[blk_idx].fw_paging_size = IWM_PAGING_BLOCK_SIZE;

        XYLog("Paging: allocated 32K bytes for firmware paging.\n");
    }

    return 0;
}

int itlwm::
iwm_save_fw_paging(struct iwm_softc *sc, const struct iwm_fw_img *fw)
{
    int ret;

    ret = iwm_alloc_fw_paging_mem(sc, fw);
    if (ret)
        return ret;

    return iwm_fill_paging_mem(sc, fw);
}

/* send paging cmd to FW in case CPU2 has paging image */
int itlwm::
iwm_send_paging_cmd(struct iwm_softc *sc, const struct iwm_fw_img *fw)
{
    int blk_idx;
    uint32_t dev_phy_addr;
    struct iwm_fw_paging_cmd fw_paging_cmd = {
        .flags =
            htole32(IWM_PAGING_CMD_IS_SECURED |
                IWM_PAGING_CMD_IS_ENABLED |
                (sc->num_of_pages_in_last_blk <<
                IWM_PAGING_CMD_NUM_OF_PAGES_IN_LAST_GRP_POS)),
        .block_size = htole32(IWM_BLOCK_2_EXP_SIZE),
        .block_num = htole32(sc->num_of_paging_blk),
    };

    /* loop for for all paging blocks + CSS block */
    for (blk_idx = 0; blk_idx < sc->num_of_paging_blk + 1; blk_idx++) {
        dev_phy_addr = htole32(
            sc->fw_paging_db[blk_idx].fw_paging_block.paddr >>
            IWM_PAGE_2_EXP_SIZE);
        fw_paging_cmd.device_phy_addr[blk_idx] = dev_phy_addr;
//        bus_dmamap_sync(sc->sc_dmat,
//            sc->fw_paging_db[blk_idx].fw_paging_block.map,
//            BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
    }

    return iwm_send_cmd_pdu(sc, iwm_cmd_id(IWM_FW_PAGING_BLOCK_CMD,
                           IWM_ALWAYS_LONG_GROUP, 0),
                    0, sizeof(fw_paging_cmd), &fw_paging_cmd);
}

int itlwm::
iwm_run_init_mvm_ucode(struct iwm_softc *sc, int justnvm)
{
    struct iwm_notification_wait calib_wait;
    static const uint16_t init_complete[] = {
        IWM_INIT_COMPLETE_NOTIF,
        IWM_CALIB_RES_NOTIF_PHY_DB
    };
    int ret;
    
    /* do not operate with rfkill switch turned on */
    if ((sc->sc_flags & IWM_FLAG_RFKILL) && !justnvm) {
        XYLog("radio is disabled by hardware switch\n");
        return EPERM;
    }
    
    iwm_init_notification_wait(sc->sc_notif_wait,
                               &calib_wait,
                               init_complete,
                               nitems(init_complete),
                               iwm_wait_phy_db_entry,
                               sc->sc_phy_db);
    
    /* Will also start the device */
    ret = iwm_load_ucode_wait_alive(sc, IWM_UCODE_INIT);
    if (ret) {
        XYLog("Failed to start INIT ucode: %d\n",
            ret);
        goto error;
    }
    
    if (sc->cfg->device_family < IWM_DEVICE_FAMILY_8000) {
        ret = iwm_send_bt_init_conf(sc);
        if (ret) {
            XYLog("failed to send bt coex configuration: %d\n", ret);
            goto error;
        }
    }
    
    if (justnvm) {
        /* Read nvm */
        ret = iwm_nvm_init(sc);
        if (ret) {
            XYLog("failed to read nvm\n");
            goto error;
        }
        if (IEEE80211_ADDR_EQ(etheranyaddr, sc->sc_ic.ic_myaddr))
        IEEE80211_ADDR_COPY(sc->sc_ic.ic_myaddr,
                            sc->nvm_data->hw_addr);
        goto error;
    }
    
    /* Send TX valid antennas before triggering calibrations */
    ret = iwm_send_tx_ant_cfg(sc, iwm_get_valid_tx_ant(sc));
    if (ret) {
        XYLog("failed to send antennas before calibration: %d\n", ret);
        goto error;
    }
    
    /*
     * Send phy configurations command to init uCode
     * to start the 16.0 uCode init image internal calibrations.
     */
    ret = iwm_send_phy_cfg_cmd(sc);
    if (ret) {
        XYLog("%s: Failed to run INIT calibrations: %d\n",
            __func__, ret);
        goto error;
    }
    
    /*
     * Nothing to do but wait for the init complete notification
     * from the firmware.
     */
    IWM_UNLOCK(sc);
    ret = iwm_wait_notification(sc->sc_notif_wait, &calib_wait,
        IWM_UCODE_CALIB_TIMEOUT);
    IWM_LOCK(sc);
    
    XYLog("%s done\n", __func__);
    
    goto out;
error:
    iwm_remove_notification(sc->sc_notif_wait, &calib_wait);
out:
    return ret;
}

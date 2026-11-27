/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * USB pmdiag: составное устройство CDC + MSC.
 * Строка продукта — не «pmtoken», поэтому программа HapasVault диагностику за токен
 * не примет; серийный номер другой (…-DIAG), чтобы Windows не путала её с токеном.
 */
#include "diag_disk.h"
#include "pico/unique_id.h"
#include "tusb.h"
#include <string.h>

enum { STR_LANG, STR_MANUF, STR_PRODUCT, STR_SERIAL, STR_CDC, STR_MSC, STR_COUNT };
enum { ITF_CDC, ITF_CDC_DATA, ITF_MSC, ITF_COUNT };

#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT   0x02
#define EP_CDC_IN    0x82
#define EP_MSC_OUT   0x03
#define EP_MSC_IN    0x83
#define CONFIG_LEN   (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + TUD_MSC_DESC_LEN)

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x1209,
    .idProduct = 0x0001,
    .bcdDevice = 0xD100,
    .iManufacturer = STR_MANUF,
    .iProduct = STR_PRODUCT,
    .iSerialNumber = STR_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t desc_config[CONFIG_LEN] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, 0, 100),
    TUD_CDC_DESCRIPTOR(ITF_CDC, STR_CDC, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
    TUD_MSC_DESCRIPTOR(ITF_MSC, STR_MSC, EP_MSC_OUT, EP_MSC_IN, 64),
};

static char serial_str[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 6];

static const char *const strings[STR_COUNT] = {
    [STR_MANUF] = "HapasVault",
    [STR_PRODUCT] = "pmdiag",
    [STR_SERIAL] = serial_str,
    [STR_CDC] = "pmdiag report",
    [STR_MSC] = "pmdiag disk",
};

const uint8_t *tud_descriptor_device_cb(void) { return (const uint8_t *)&desc_device; }

const uint8_t *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_config;
}

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    static uint16_t out[34];
    if (!serial_str[0]) {
        pico_get_unique_board_id_string(serial_str, sizeof serial_str);
        strcat(serial_str, "-DIAG");
    }
    uint8_t len;
    if (index == STR_LANG) {
        out[1] = 0x0409;
        len = 1;
    } else {
        if (index >= STR_COUNT || !strings[index]) return NULL;
        const char *s = strings[index];
        for (len = 0; len < 33 && s[len]; len++) out[1 + len] = (uint8_t)s[len];
    }
    out[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * len + 2));
    return out;
}

/* ---------------- MSC: диск только для чтения ---------------- */

void tud_msc_inquiry_cb(uint8_t lun, uint8_t vendor_id[8], uint8_t product_id[16], uint8_t product_rev[4])
{
    (void)lun;
    memcpy(vendor_id, "HapasVlt", 8);
    memcpy(product_id, "pmdiag report   ", 16);
    memcpy(product_rev, "1.0 ", 4);
}

bool tud_msc_test_unit_ready_cb(uint8_t lun)
{
    (void)lun;
    return true;
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count, uint16_t *block_size)
{
    (void)lun;
    *block_count = DISK_SECTORS;
    *block_size = DISK_SECTOR;
}

bool tud_msc_start_stop_cb(uint8_t lun, uint8_t power_condition, bool start, bool load_eject)
{
    (void)lun; (void)power_condition; (void)start; (void)load_eject;
    return true;
}

bool tud_msc_is_writable_cb(uint8_t lun)
{
    (void)lun;
    return false;
}

int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset, void *buffer, uint32_t bufsize)
{
    (void)lun;
    uint8_t *out = buffer;
    uint32_t done = 0;
    while (done < bufsize) {
        uint32_t pos = offset + done;
        uint32_t sec = lba + pos / DISK_SECTOR, in = pos % DISK_SECTOR;
        if (sec >= DISK_SECTORS) return -1;
        uint8_t tmp[DISK_SECTOR];
        disk_read_sector(sec, tmp);
        uint32_t n = DISK_SECTOR - in < bufsize - done ? DISK_SECTOR - in : bufsize - done;
        memcpy(out + done, tmp + in, n);
        done += n;
    }
    return (int32_t)done;
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize)
{
    (void)lun; (void)lba; (void)offset; (void)buffer; (void)bufsize;
    tud_msc_set_sense(lun, SCSI_SENSE_DATA_PROTECT, 0x27, 0x00);
    return -1;
}

int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16], void *buffer, uint16_t bufsize)
{
    (void)buffer; (void)bufsize;
    switch (scsi_cmd[0]) {
    case 0x1E:                          /* PREVENT ALLOW MEDIUM REMOVAL */
        return 0;
    default:
        tud_msc_set_sense(lun, SCSI_SENSE_ILLEGAL_REQUEST, 0x20, 0x00);
        return -1;
    }
}

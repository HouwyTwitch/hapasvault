/* USB: одно устройство CDC ACM («виртуальный COM-порт»), драйвер встроен в ОС. */
#include "proto.h"
#include "pico/unique_id.h"
#include "tusb.h"

enum { STR_LANG, STR_MANUF, STR_PRODUCT, STR_SERIAL, STR_CDC, STR_COUNT };
enum { ITF_CDC, ITF_CDC_DATA, ITF_COUNT };

#define EP_CDC_NOTIF 0x81
#define EP_CDC_OUT   0x02
#define EP_CDC_IN    0x82
#define CONFIG_LEN   (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)

static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = PM_USB_VID,
    .idProduct = PM_USB_PID,
    .bcdDevice = 0x0100 | PM_PROTO_VERSION,
    .iManufacturer = STR_MANUF,
    .iProduct = STR_PRODUCT,
    .iSerialNumber = STR_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t desc_config[CONFIG_LEN] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_LEN, 0, 100),
    TUD_CDC_DESCRIPTOR(ITF_CDC, STR_CDC, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};

static char serial_str[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2 + 1];

static const char *const strings[STR_COUNT] = {
    [STR_MANUF] = "HapasVault",
    [STR_PRODUCT] = "pmtoken",
    [STR_SERIAL] = serial_str,
    [STR_CDC] = "pmtoken",
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
    if (!serial_str[0]) pico_get_unique_board_id_string(serial_str, sizeof serial_str);
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

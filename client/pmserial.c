#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <setupapi.h>
#  include <devguid.h>
#else
#  define _DEFAULT_SOURCE
#  include <dirent.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <sys/ioctl.h>
#  include <termios.h>
#  include <unistd.h>
#endif

#include "pmserial.h"
#include "framer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32

/* ---------------- Windows ---------------- */

typedef struct {
    HANDLE h;
    DWORD  timeout;
} serial_win;

int pm_serial_find(char *path, size_t cap)
{
    wchar_t want[32];
    swprintf(want, 32, L"VID_%04X&PID_%04X", PM_USB_VID, PM_USB_PID);
    HDEVINFO set = SetupDiGetClassDevsW(&GUID_DEVCLASS_PORTS, NULL, NULL, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) return 0;
    int found = 0;
    SP_DEVINFO_DATA dev;
    dev.cbSize = sizeof dev;
    for (DWORD i = 0; !found && SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        wchar_t ids[1024];
        if (!SetupDiGetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID, NULL, (BYTE *)ids, sizeof ids - 4, NULL))
            continue;
        ids[sizeof ids / sizeof ids[0] - 1] = 0;
        ids[sizeof ids / sizeof ids[0] - 2] = 0;
        int match = 0;
        for (wchar_t *p = ids; *p; p += wcslen(p) + 1)        /* REG_MULTI_SZ */
            if (wcsstr(_wcsupr(p), want)) match = 1;
        if (!match) continue;
        HKEY key = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (key == INVALID_HANDLE_VALUE) continue;
        wchar_t name[32];
        DWORD type = 0, size = sizeof name - sizeof name[0];
        if (RegQueryValueExW(key, L"PortName", NULL, &type, (BYTE *)name, &size) == ERROR_SUCCESS && type == REG_SZ) {
            name[size / sizeof name[0]] = 0;
            if (WideCharToMultiByte(CP_UTF8, 0, name, -1, path, (int)cap, NULL, NULL) > 0) found = 1;
        }
        RegCloseKey(key);
    }
    SetupDiDestroyDeviceInfoList(set);
    return found;
}

pm_serial pm_serial_open(const char *path, int timeout_ms, int *busy)
{
    wchar_t dev[64];
    swprintf(dev, 64, L"\\\\.\\%hs", path);         /* COM10 и выше — только так */
    HANDLE h = CreateFileW(dev, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    *busy = h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED;
    if (h == INVALID_HANDLE_VALUE) return PM_BAD_SERIAL;
    DCB dcb;
    memset(&dcb, 0, sizeof dcb);
    dcb.DCBlength = sizeof dcb;
    GetCommState(h, &dcb);
    dcb.BaudRate = 115200;                          /* для USB CDC значения не имеет */
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = FALSE;
    dcb.fOutX = dcb.fInX = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;           /* DTR = «программа подключена» */
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    COMMTIMEOUTS t;
    memset(&t, 0, sizeof t);
    t.ReadTotalTimeoutConstant = (DWORD)timeout_ms;
    t.WriteTotalTimeoutConstant = (DWORD)timeout_ms;
    serial_win *s = malloc(sizeof *s);
    if (!s || !SetCommState(h, &dcb) || !SetCommTimeouts(h, &t)) {
        free(s);
        CloseHandle(h);
        return PM_BAD_SERIAL;
    }
    EscapeCommFunction(h, SETDTR);
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    s->h = h;
    s->timeout = (DWORD)timeout_ms;
    return (pm_serial)s;
}

void pm_serial_close(pm_serial ps)
{
    if (ps == PM_BAD_SERIAL) return;
    serial_win *s = (serial_win *)ps;
    EscapeCommFunction(s->h, CLRDTR);
    CloseHandle(s->h);
    free(s);
}

static int write_all(pm_serial ps, const uint8_t *p, size_t n)
{
    serial_win *s = (serial_win *)ps;
    while (n) {
        DWORD k = 0;
        if (!WriteFile(s->h, p, (DWORD)n, &k, NULL) || k == 0) return -1;
        p += k; n -= k;
    }
    return 0;
}

static int read_all(pm_serial ps, uint8_t *p, size_t n)
{
    serial_win *s = (serial_win *)ps;
    while (n) {
        DWORD k = 0;
        if (!ReadFile(s->h, p, (DWORD)n, &k, NULL) || k == 0) return -1;   /* k == 0: таймаут */
        p += k; n -= k;
    }
    return 0;
}

#else

/* ---------------- POSIX ---------------- */

typedef struct {
    int fd;
    int timeout;
} serial_posix;

static unsigned read_hex(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned v = 0;
    if (fscanf(f, "%x", &v) != 1) v = 0;
    fclose(f);
    return v;
}

int pm_serial_find(char *path, size_t cap)
{
    /* /sys/class/tty/ttyACMn/device — интерфейс USB, родитель — устройство с idVendor */
    DIR *d = opendir("/sys/class/tty");
    if (!d) return 0;
    int found = 0;
    struct dirent *e;
    while (!found && (e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "ttyACM", 6) != 0) continue;
        char p[512];
        snprintf(p, sizeof p, "/sys/class/tty/%s/device/../idVendor", e->d_name);
        unsigned vid = read_hex(p);
        snprintf(p, sizeof p, "/sys/class/tty/%s/device/../idProduct", e->d_name);
        unsigned pid = read_hex(p);
        if (vid == PM_USB_VID && pid == PM_USB_PID &&
            (size_t)snprintf(path, cap, "/dev/%s", e->d_name) < cap)
            found = 1;
    }
    closedir(d);
    return found;
}

pm_serial pm_serial_open(const char *path, int timeout_ms, int *busy)
{
    int fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    *busy = fd < 0 && errno == EBUSY;
    if (fd < 0) return PM_BAD_SERIAL;
    struct termios t;
    if (tcgetattr(fd, &t) != 0) { close(fd); return PM_BAD_SERIAL; }
    cfmakeraw(&t);
    t.c_cflag |= CLOCAL | CREAD | HUPCL;            /* закрытие = сброс DTR = токен блокируется */
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    serial_posix *s = malloc(sizeof *s);
    if (ioctl(fd, TIOCEXCL) != 0 && errno == EBUSY) *busy = 1;
    if (*busy || !s || tcsetattr(fd, TCSANOW, &t) != 0) {
        free(s);
        close(fd);
        return PM_BAD_SERIAL;
    }
    tcflush(fd, TCIOFLUSH);
    s->fd = fd;
    s->timeout = timeout_ms;
    return (pm_serial)s;
}

void pm_serial_close(pm_serial ps)
{
    if (ps == PM_BAD_SERIAL) return;
    serial_posix *s = (serial_posix *)ps;
    close(s->fd);
    free(s);
}

static int wait_fd(serial_posix *s, short ev)
{
    struct pollfd p = {s->fd, ev, 0};
    int r;
    do r = poll(&p, 1, s->timeout > 0 ? s->timeout : -1);
    while (r < 0 && errno == EINTR);
    return r > 0 && (p.revents & ev) ? 0 : -1;
}

static int write_all(pm_serial ps, const uint8_t *p, size_t n)
{
    serial_posix *s = (serial_posix *)ps;
    while (n) {
        if (wait_fd(s, POLLOUT) != 0) return -1;
        ssize_t k = write(s->fd, p, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return -1;
        p += k; n -= (size_t)k;
    }
    return 0;
}

static int read_all(pm_serial ps, uint8_t *p, size_t n)
{
    serial_posix *s = (serial_posix *)ps;
    while (n) {
        if (wait_fd(s, POLLIN) != 0) return -1;
        ssize_t k = read(s->fd, p, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return -1;                       /* 0 после POLLIN = устройство пропало */
        p += k; n -= (size_t)k;
    }
    return 0;
}

#endif

long pm_serial_xfer(void *ctx, const uint8_t *req, size_t req_len, uint8_t *resp, size_t cap)
{
    pm_serial s = *(pm_serial *)ctx;
    if (s == PM_BAD_SERIAL) return -1;
    uint8_t h[4];
    pm_framer_header(h, req_len);
    if (write_all(s, h, 4) != 0 || write_all(s, req, req_len) != 0) return -1;
    if (read_all(s, h, 4) != 0) return -1;
    size_t len = (size_t)h[0] | (size_t)h[1] << 8 | (size_t)h[2] << 16 | (size_t)h[3] << 24;
    if (len > cap || read_all(s, resp, len) != 0) return -1;
    return (long)len;
}

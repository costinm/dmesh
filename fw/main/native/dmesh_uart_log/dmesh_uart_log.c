#include <stdarg.h>
#include <stdio.h>

// We want main to send all logs to a handler that can save last few lines and use QUIC handler over wifi
// instead of serial. This is configured with esp_log_set_vprintf.

extern int dmesh_uart_log_line(const unsigned char *bytes, size_t len);

int dmesh_uart_log_vprintf(const char *format, va_list args)
{
    char line[256];
    int written = vsnprintf(line, sizeof(line), format, args);
    if (written <= 0) return written;
    size_t used = (size_t)written;
    if (used >= sizeof(line)) used = sizeof(line) - 1u;
    (void)dmesh_uart_log_line((const unsigned char *)line, used);
    return written;
}

#include "time.h"
void get_time(char *tempo, size_t size) {
    time_t timer;
    time(&timer);
    struct tm *tm_info = localtime(&timer);
    strftime(tempo, size, "%Y-%m-%dT%H:%M:%S", tm_info);
}
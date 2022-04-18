//
// Created by gilee on 2022/04/15.
//

#ifndef WEBSERV_OPTIONS_HPP
#define WEBSERV_OPTIONS_HPP

#include <getopt.h>

#define USAGE "[--port=n] [--chroot --user=u --group=g] <docroot>"
int debug_mode = 0;

struct option longopts[] = {
        {"debug", no_argument, &debug_mode, 1},
        {"chroot", no_argument, NULL, 'c'},
        {"user", required_argument, NULL, 'u'},
        {"group", required_argument, NULL, 'g'},
        {"port", required_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
};
#endif //WEBSERV_OPTIONS_HPP

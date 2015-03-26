/*
 * evdev.c - Support for evdev devices.
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Kyle J. Temkin <temkink@ainfosec.com>
 *
 * Support for absolute-coordinate linux event devices, such as touchscreens, some
 * touchpads, and pen tablets. Some code used from 
 *
 *   http://www.home.unix-ag.org/simon/files/mt-evtest.c
 *
 * which is in the public domain.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 ********/

#ifndef __GPM_EVDEV_H__
#define __GPM_EVDEV_H__

#ifdef HAVE_LINUX_INPUT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <poll.h>
#include <string.h>
#include <inttypes.h>

#include <linux/input.h>

//Used only to get the window size.
#include "headers/daemon.h"

struct evdev_touch_point {
  int32_t x;
  int32_t y;
};

/**
 * Structure representing an evdev absolute pointing device.
 */  
struct evdev_absolute_device {

   //The file descriptor used to communicate with the given evdev device.
   int fd;

   //True iff the given device supports multitouch.
   char is_multitouch;

   //Store the two screen corners, which denote the limitations of the 
   //screen events, as reported by evdev.
   struct evdev_touch_point maxima, minima;
};


//Initialize our event device support.
extern Gpm_Type * initialize_evdev_absolute_device(int fd, unsigned short flags, struct Gpm_Type *type, int argc, char **argv);

//Support absolute evdev devices separately, to minimize our patch 
//surface area and thus increase version compatibility. 
extern int process_evdev_absolute_event(Gpm_Event * state, unsigned char *data);


#endif 

#endif

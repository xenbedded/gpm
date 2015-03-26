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

#ifdef HAVE_LINUX_INPUT_H

#include "headers/gpmInt.h"
#include "headers/daemon.h"
#include "headers/message.h"
#include "headers/evdev.h"

struct evdev_absolute_device evdev_device;

/**
 * Evdev returns certain bitfields as large array of raw binary data.
 *
 * To help deal with this data efficiently, we break it into an array of 
 * "chunks". The following typedef specifies the type of those chunks.
 *
 * This can be theoretically any data type-- the code below should adjust 
 * accordingly.
 */ 
typedef unsigned long evdev_bitfield_t;

// Store the platform-specific number of bytes per bitfield "chunk".
static const size_t bits_per_field = sizeof(evdev_bitfield_t) * 8;

//The threshold above which a pen should be considered pressed.
//Ideally, we'd get a threshold (or limit) from evdev, but it doesn't provide one.
static const int pen_pressure_threshold = 30;

//Forward declarations. See below.
static inline int test_bit(evdev_bitfield_t * bitflags, size_t bit_number);
static inline int is_absolute_device(struct evdev_absolute_device * device);
static inline int is_multitouch_device(struct evdev_absolute_device * device);
static void announce_evdev_device_open(struct evdev_absolute_device * device);
static void identify_screen_limits(struct evdev_absolute_device * device);

/**
 * Initialize our internal representation of an evdev absolute (tablet) device.
 */
Gpm_Type * initialize_evdev_absolute_device(int fd, unsigned short flags, struct Gpm_Type *type, int argc, char **argv) 
{
   //This simple shortcut allows us to adjust this function to use an object model later, if we so choose.
   struct evdev_absolute_device * device = &evdev_device;

   //Attach the opened file descriptor to our new device object.
   device->fd = fd;

   //Announce to the user that we've opened the given evdev device.
   announce_evdev_device_open(device);

   //And verify we've been passed an absolute device.
   if(!is_absolute_device(device)) {
       gpm_report(GPM_PR_ERR, "This device does not produce absolute events. Use the normal evdev driver, instead.");
       return NULL;
   }

   //If this is a multitouch device, set its multitouch flag. 
   device->is_multitouch = is_multitouch_device(device);

   //And print out whether this is a multitouch device.
   if(device->is_multitouch) {
       gpm_report(GPM_PR_DEBUG, "This is a multitouch device.");
   } else {
       gpm_report(GPM_PR_DEBUG, "This is not a multitouch device.");
   }

   //Identify the limits of the screen, which we'll use to scale our absolute events to a reasonable size.
   identify_screen_limits(device);

   //And return the relevant device type.
   return type;
}


/**
 * Determines (and updates) the device's "screen limits"-- which map the event locations of
 * the corners of the screen, determining the maximum and minimum possible event values.
 *
 * Uses the provided events as the type of events expected form the given screen.
 *
 * @param device The device to be updated.
 * @param x_type The event for X AXIS events. Typically ABS_X or ABS_MT_POSITION_X.
 * @param y_type The event for Y AXIS events. Typically ABS_Y or ABS_MT_POSITION_Y.
 */
static void __identify_screen_limits_using_parameters(struct evdev_absolute_device * device, int x_type, int y_type)
{
   struct input_absinfo limit_info;

   //Retrieve the x-axis limitations, and use them to populate the relevant structure.
   ioctl(device->fd, EVIOCGABS(x_type), &limit_info);
   device->maxima.x = limit_info.maximum;
   device->minima.x = limit_info.minimum;
   gpm_report(GPM_PR_DEBUG, "Screen width: %ld, %ld", device->minima.x, device->maxima.x);

   //And repeat for the y axis.
   ioctl(device->fd, EVIOCGABS(y_type), &limit_info);
   device->maxima.y = limit_info.maximum;
   device->minima.y = limit_info.minimum;
   gpm_report(GPM_PR_DEBUG, "Screen height: %ld, %ld", device->minima.y, device->maxima.y);
}



/**
 * Determines (and updates) the device's "screen limits"-- which map the event locations of
 * the corners of the screen, determining the maximum and minimum possible event values.
 *
 * @param device The device to be updated.
 */
static void identify_screen_limits(struct evdev_absolute_device * device) 
{
   //If we have a multitouch device, query the limits for the multitouch events...
   if(device->is_multitouch) {
      __identify_screen_limits_using_parameters(device, ABS_MT_POSITION_X, ABS_MT_POSITION_Y);
   } 
   //Otherwise, use the normal absolute events.
   else {
      __identify_screen_limits_using_parameters(device, ABS_X, ABS_Y);
   }

}


/**
 * Announces to the debug console that the provided evdev device has been opened.
 *
 * @param device The device whose name should be announced.
 */ 
static void announce_evdev_device_open(struct evdev_absolute_device * device) {
   char name[256] = "Unknown Device";

   //First, grab and print the device's name.
   ioctl (device->fd, EVIOCGNAME(sizeof(name)), name);
   gpm_report(GPM_PR_INFO, "Opened linux event device: %s", name);
}


/**
 * Returns true iff the given device can generate evdev absolute events.
 */
static int is_absolute_device(struct evdev_absolute_device * device) {
   evdev_bitfield_t event_info[(EV_MAX / bits_per_field) + 1];
   int ret;

   //Ask the given evdev device for information regarding its capabilities.
   ret = ioctl (device->fd, EVIOCGBIT(0, EV_MAX), event_info);

   //If we failed to execute the IOCTL, assume this isn't a valid absolute
   //device.
   if(ret < 0) {
      gpm_report(GPM_PR_ERR, "Failed to determine whether this was an absolute device (%s)", strerror(errno));
      return 0; 
   }

   //And return true iff the absolute events flag is set.
   return test_bit(event_info, EV_ABS);

}

/**
 * Simple quirk method that identifies whether the given device can identify
 * a multi-touch screen limit. Returns truee iff a valid limit is found.
 *
 */ 
static int __quirk_test_multitouch_screen_maxima(struct evdev_absolute_device * device) 
{
   struct input_absinfo limit_info;

   //Attempt to read the device's X screen limit...
   ioctl(device->fd, EVIOCGABS(ABS_MT_POSITION_X), &limit_info);

   //... and return true iff a valid limit was found.
   return (limit_info.maximum > 0);

}



/**
 * Returns true iff the given device can generate evdev multitouch events.
 */
static int is_multitouch_device(struct evdev_absolute_device * device) {
   evdev_bitfield_t event_info[KEY_MAX / bits_per_field + 1];

   int is_multitouch = 0;

   //Ask the given evdev device for information regarding the events it generates.
   ioctl (device->fd, EVIOCGBIT(EV_ABS, KEY_MAX), event_info);

   //And return true iff the absolute events flag is set.
   is_multitouch = test_bit(event_info, ABS_MT_POSITION_X) && test_bit(event_info, ABS_MT_POSITION_Y);

   //QUIRK:
   //If the device advertises being multi-touch, but can't provide screen limits, ignore its multitouch nature.
   if(is_multitouch && !__quirk_test_multitouch_screen_maxima(device)) {
      is_multitouch = 0;
   }
   

   return is_multitouch;

}


/**
 * We consider the large bitfields returned by evdev to be an array of
 * individual bitfields. This quick method determines which array index
 * will house a given bit number.
 */
static inline size_t array_index_for(size_t bit_number) {
    return bit_number / bits_per_field;
}

/**
 * Produces a bitmask which can be used to check whether a given bit
 * number is set inside of an evdev_bitfield. 
 */ 
static inline evdev_bitfield_t bit_mask_for(size_t bit_number) {
    return 1UL << (bit_number % bits_per_field);
}

/**
 * Returns true iff the given bit is set in the evdev capabilities blob.
 */ 
static inline int test_bit(evdev_bitfield_t * bitflags, size_t bit_number) {
   
    //Determine the location of a given bit in the binary array...
    size_t field_number = array_index_for(bit_number);
  
    //... and use to to get the bitfield containing the relevant bit.
    unsigned long bit_field = bitflags[field_number];

    //Return true iff the given bit is set in the evdev capabilities blob.
    return bit_field && bit_mask_for(bit_number);
}

/**
 * Scales the provided evdev touch event "location" value for use in GPM.
 *
 * @param value The evdev event value, which should represent an X/Y coordinate for an evdev pointer event.
 * @param value The minimum possible value produced by the relevant evdev event.
 * @param value The maximum possible value produced by the relevant evdev event.
 * @param value The number of rows /or/ columns in the window. If this is an X event, columns should be provided;
 *    otherwise, the number of columns should be provided.
 */
short __scale_event_value_for_gpm(int32_t value, int32_t evdev_min, int32_t evdev_max, short window_size) {

   //General formula:
   //
   //value - min (event offset)          result
   //--------------------------   ==   ---------- 
   // max - min   (evdev size)         window_size
  

   //Compute the event offset-- how far this event happened from the screen edge.
   int32_t event_offset  = value - evdev_min;

   //And compute the total "span" of the screen.
   int32_t evdev_size    = evdev_max - evdev_min;

   //Compute the scaled event value.
   return (event_offset * window_size) / evdev_size;
}


/**
 * Adjusts the state of a given GPM mouse button.
 *
 * @param state The Gpm_Event object to be adjusted.
 * @param button The GPM constant for the button to be adjusted.
 * @param pressed True iff the button should be considered pressed.
 */ 
void set_gpm_button_state(Gpm_Event * state, unsigned char button, int pressed) {

   //If the given button should be pressed, set its bit flag.
   if(pressed) {
      state->buttons |= button; 
   } 
   //Otherwise, clear its flag.
   else {
      state->buttons &= ~button;
   }
}


/**
 * Uses an evdev keypress to populate a GPM event, 
 * effectively relaying button presses to GPM.
 *
 * @param device The device which is sending the given event.
 * @param event The event to be processed.
 * @param state The GPM state to be modified.
 *
 */
void process_pen_pressure(struct evdev_absolute_device * device, struct input_event * event, Gpm_Event * state) {

   //Reduce non-binary events down to "pressed" or "not pressed".
   int button_pressed = (event->value > pen_pressure_threshold);

   //And interpret pen pressure as left button presses.
   set_gpm_button_state(state, GPM_B_LEFT, button_pressed);
}


void force_pen_release(struct evdev_absolute_device * device, struct input_event * event, Gpm_Event * state) {
   set_gpm_button_state(state, GPM_B_LEFT, 0);
}


/**
 * Uses an evdev keypress to populate a GPM event, 
 * effectively relaying button presses to GPM.
 *
 * @param device The device which is sending the given event.
 * @param event The event to be processed.
 * @param state The GPM state to be modified.
 *
 */
void process_button_press(struct evdev_absolute_device * device, struct input_event * event, Gpm_Event * state) {

   //Reduce non-binary events down to "pressed" or "not pressed".
   int button_pressed = (event->value > 0);

   //Use the relevant event code to determine which button is being pressed,
   //and adjust the state accordingly.
   switch(event->code) {
     
      case BTN_STYLUS:
      case BTN_RIGHT:
      case BTN_TOOL_RUBBER:
         set_gpm_button_state(state, GPM_B_RIGHT, button_pressed);
         break;

      case BTN_STYLUS2:
      case BTN_MIDDLE:
      case BTN_SIDE:
         set_gpm_button_state(state, GPM_B_MIDDLE, button_pressed);
         break;

      case BTN_LEFT:
      case BTN_TOUCH:
         set_gpm_button_state(state, GPM_B_LEFT, button_pressed);
         break;

      //Ignore "tool pen" events; these indicate when the pen enters
      //or exits our range.
      case BTN_TOOL_PEN:
         break;
   }

}


/**
 * Uses an evdev absolute movement (EV_ABS) to populate a GPM event,
 * effectively relaying an X and Y coordinate to GPM.
 *
 * @param device The device which is sending the given event.
 * @param event The event to be processed.
 * @param state The GPM state to be modified.
 *
 */
void process_absolute_movement(struct evdev_absolute_device * device, struct input_event * event, Gpm_Event * state) {

   //Use the relevant event to set either the x or y position of the cursor, scaling appropriately.
   switch(event->code) {
     
      case ABS_X:
      case ABS_MT_POSITION_X:
         state->x = __scale_event_value_for_gpm(event->value, device->minima.x, device->maxima.x, win.ws_col);
         break;


      case ABS_Y:
      case ABS_MT_POSITION_Y:
         state->y = __scale_event_value_for_gpm(event->value, device->minima.y, device->maxima.y, win.ws_row);
         break;

      //Special case:  if we have a pressure (pen down) or misc (pen up) event, 
      //handle it as a button press instead of an absolute motion event.
      case ABS_PRESSURE:
         process_pen_pressure(device, event, state);
         break;

      //case ABS_MISC:
      //   force_pen_release(device, event, state);
      //   break;

      default: 
         gpm_report(GPM_PR_WARN, "Unknown EV_ABS code: %d", event->code);
         break;

   }
}

//Support absolute evdev devices separately, to minimize our patch 
//surface area and thus increase version compatibility. 
int process_evdev_absolute_event(Gpm_Event * state, unsigned char * data)
{

   //This simple shortcut allows us to adjust this function to use an object model later, if we so choose.
   struct evdev_absolute_device * device = &evdev_device;

   //Convert the data read from the event device into an input-event structure.
   struct input_event * event = (struct input_event *) data;

   switch(event->type) {

      //Handle our absolute movement types.
      case EV_ABS:
         process_absolute_movement(device, event, state);
         break;

      //Handle our simple button press types.
      case EV_KEY:
         process_button_press(device, event, state);
         break;

      //Skip seperators.
      case EV_SYN:
         break;
   
      default:
         gpm_report(GPM_PR_WARN, "Unknown event type code: %d", event->code);

   }

   return 0;
}


#endif

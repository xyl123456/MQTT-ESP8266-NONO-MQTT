/*
 * process_data.h
 *
 *  Created on: 2018Äê6ÔÂ6ÈÕ
 *      Author: Administrator
 */

#ifndef APP_INCLUDE_PROCESS_DATA_H_
#define APP_INCLUDE_PROCESS_DATA_H_

#include "os_type.h"
#include "mem.h"
#include "mqtt/mqtt.h"

typedef struct process_data
{
  uint8_t* data;
  uint16_t length;

} process_data_t;

extern MQTT_Client *process_client;

extern void data_process( process_data_t*process_data);
extern void mqtt_data_process( process_data_t* process);
#endif /* APP_INCLUDE_PROCESS_DATA_H_ */

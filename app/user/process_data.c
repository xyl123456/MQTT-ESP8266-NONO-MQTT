/*
 * process_data.c
 *
 *  Created on: 2018年6月6日
 *      Author: Administrator
 */

#include "process_data.h"
#include "mqtt_config.h"
#include "mqtt/mqtt_msg.h"
#include "mqtt/debug.h"
#include "mqtt/mqtt.h"

#include "string.h"
#include "cJSON.h"
#include "mqtt_config.h"
#include "user_config.h"

#include "user_interface.h"


MQTT_Client *process_client;

void ICACHE_FLASH_ATTR data_process( process_data_t* process)
{
	cJSON * root = cJSON_Parse(process->data);
	if (NULL != root) {
			if (cJSON_HasObjectItem(root, "message")) {
				cJSON *string = cJSON_GetObjectItem(root, "message");
				if (cJSON_IsString(string)) {
					char *s = cJSON_Print(string);
#ifdef DBUG_MODE
					os_printf("string: %s\r\n", s);
#endif
					if(memcmp(s,"\"success\"",9)==0)
					{
					//数据正常，发送到对应的topic
					MQTT_Publish(process_client, PUBLISH_TOPIC, process->data, process->length, 0, 0);
						/*test 0xff data
						char data_buf[15]={0xEB,0x90,0x11,0x22,0x33,0x44,0xFF,0xFF,0xFF,0xFE,0x44,0x33,0x22,0x11,0xFF};
						MQTT_Publish(process_client, PUBLISH_TOPIC, data_buf, 15, 0, 0);
						*/
					}
					cJSON_free((void *) s);
				}
			}
			cJSON_Delete(root);
		} else {
#ifdef DBUG_MODE
			INFO("\r\nparse error!\r\n");
#endif
		}
}

void ICACHE_FLASH_ATTR mqtt_data_process( process_data_t* process)
{
	cJSON * root = cJSON_Parse(process->data);
		if (NULL != root) {
				if (cJSON_HasObjectItem(root, "message")) {
					cJSON *string = cJSON_GetObjectItem(root, "message");
					if (cJSON_IsString(string)) {
						char *s = cJSON_Print(string);
#ifdef DBUG_MODE
						os_printf("string: %s\r\n", s);
#endif
						if(memcmp(s,"\"success\"",9)==0)
						{
						//数据正常，发送到对应的设备解析
							uart0_tx_buffer(process->data,process->length);
						}
						cJSON_free((void *) s);
					}
				}
				cJSON_Delete(root);
			}
		else {

			}
}


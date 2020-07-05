/* Copyright (C) 2005-2013 IP2Location.com
 * All Rights Reserved
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the MIT license
 */

#include "IP2Location.h"
#include <string.h>
#include <stdio.h>

int main()
{
    char ipAddress[30];
    int exit = 0;

#ifdef WIN32
    IP2Location *IP2LocationObj = IP2Location_open("data\\IP2LOCATION-LITE-DB11.IPV6.BIN");
#else
    IP2Location *IP2LocationObj = IP2Location_open("data/IP2LOCATION-LITE-DB11.IPV6.BIN");
#endif
    IP2LocationRecord *record = NULL;

    printf("IP2Location API version: %s (%lu)\n", IP2Location_api_version_string(), IP2Location_api_version_num());

    if (IP2LocationObj == NULL)
    {
        printf("Please install the database in correct path.\n");
        return -1;
    }

    if (IP2Location_open_mem(IP2LocationObj, IP2LOCATION_SHARED_MEMORY) == -1)
    {
        fprintf(stderr, "IPv4: Call to IP2Location_open_mem failed\n");
    }
    while (exit != 1)
    {
        printf("digita ae cupixa: ");
        scanf("%30[^\n]",ipAddress);
        scanf("%*c");
        printf("\nvc digitou %s\n",ipAddress);
        if (strcmp(ipAddress, "q") != 0)
        {
            record = IP2Location_get_all(IP2LocationObj, ipAddress);
            if (record != NULL)
            {
                const char *output =
                    "Ip %s encontrado: \n"
                    "region: %s \n"
                    "areacode: %s \n"
                    "city: %s \n"
                    "country_long: %s \n"
                    "country_short: %s \n"
                    "domain: %s \n"
                    "elevation: %f \n"
                    "iddcode: %s \n"
                    "isp: %s \n"
                    "latitude: %f \n"
                    "longitude: %f \n"
                    "mcc: %s \n"
                    "mnc: %s \n"
                    "mobilebrand: %s \n"
                    "netspeed: %s \n"
                    "timezone: %s \n"
                    "usagetype: %s \n"
                    "weatherstationcode: %s \n"
                    "weatherstationname: %s \n"
                    "zipcode: %s \n";

                printf(output,
                       ipAddress,
                       record->region,
                       record->areacode,
                       record->city,
                       record->country_long,
                       record->country_short,
                       record->domain,
                       record->elevation,
                       record->iddcode,
                       record->isp,
                       record->latitude,
                       record->longitude,
                       record->mcc,
                       record->mnc,
                       record->mobilebrand,
                       record->netspeed,
                       record->timezone,
                       record->usagetype,
                       record->weatherstationcode,
                       record->weatherstationname,
                       record->zipcode);
                IP2Location_free_record(record);
            }
            else
            {
                printf("ip %s não encontrado", ipAddress);
            }
        }
        else
        {
            exit = 1;
        }
    }

    IP2Location_close(IP2LocationObj);
    /*Below call will delete the shared memory unless if any other process is attached it. 
	 *if any other process is attached to it, shared memory will be closed when last process
	 *attached to it closes the shared memory 
	 *If any process call IP2Location_delete_shm, next process which IP2Location_open_mem
	 *with shared memory option, will open the new shared memory.Deleted memory will not be available for
	 * any new process but will be accesible for the processes which are already using it. 
	 */
    IP2Location_delete_shm();

    system("pause"); // this will stop the pause
    return 0;
}

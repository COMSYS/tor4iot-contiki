/*
 * Copyright (c) 2018, OpenMote Technologies, S.L.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/*---------------------------------------------------------------------------*/
/**
 * \addtogroup openmote-sensors
 * @{
 *
 * \defgroup openmote-si70x-sensor SI70X sensor
 * @{
 *
 * \file
 * Header file for the SI70X temperature and humidity sensor driver
 *
 * \author
 * Pere Tuset <peretuset@openmote.com>
 */
/*---------------------------------------------------------------------------*/
#include "lib/sensors.h"
/*---------------------------------------------------------------------------*/
#ifndef SI70X_H_
#define SI70X_H_
/*---------------------------------------------------------------------------*/
#define SI70X_ERROR             (-1)
#define SI70X_SUCCESS           (0)
#define SI70X_ACTIVATE          (SENSORS_ACTIVE)
#define SI70X_READ_RAW_TEMP     (2)
#define SI70X_READ_RAW_RHUM     (3)
#define SI70X_READ_TEMP         (4)
#define SI70X_READ_RHUM         (5)
#define SI70X_RESET             (6)
#define SI70X_NONE              (7)
/*---------------------------------------------------------------------------*/
#define SI70X_SENSOR "SI70X Sensor"
/*---------------------------------------------------------------------------*/
extern const struct sensors_sensor si70x;
/*---------------------------------------------------------------------------*/
#endif /* SI70X_H_ */
/*---------------------------------------------------------------------------*/
/**
 * @}
 * @}
 */

/*
 * Copyright (C) 2010 AG Projects
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

#include <string.h>

#include <pjmedia/mixer_port.h>
#include <pjmedia/errno.h>
#include <pj/assert.h>
#include <pj/pool.h>
#include <pj/string.h>


#define SIGNATURE   PJMEDIA_SIG_PORT_MIXER
#define MIN(a, b)   ((a)>(b)?(b):(a))

struct mixer_port
{
    pjmedia_port        base;
    pjmedia_frame_type  last_frame_type;
    pj_size_t           last_frame_size;
    pj_timestamp        last_frame_timestamp;
    pj_int16_t*         buffer;
    pj_size_t           buffer_size;
};

static pj_status_t mixer_get_frame(pjmedia_port *port, pjmedia_frame *frame);
static pj_status_t mixer_put_frame(pjmedia_port *port, pjmedia_frame *frame);
static pj_status_t mixer_on_destroy(pjmedia_port *port);


PJ_DEF(pj_status_t) pjmedia_mixer_port_create(pj_pool_t *pool,
                                              unsigned sampling_rate,
                                              unsigned channel_count,
                                              unsigned samples_per_frame,
                                              unsigned bits_per_sample,
                                              pjmedia_port **p_port)
{
    struct mixer_port *port;
    const pj_str_t name = pj_str("mixer-port");

    PJ_ASSERT_RETURN(pool && p_port, PJ_EINVAL);

    port = PJ_POOL_ZALLOC_T(pool, struct mixer_port);
    PJ_ASSERT_RETURN(port != NULL, PJ_ENOMEM);

    pjmedia_port_info_init(&port->base.info, &name, SIGNATURE, sampling_rate,
                           channel_count, bits_per_sample, samples_per_frame);

    port->base.get_frame = &mixer_get_frame;
    port->base.put_frame = &mixer_put_frame;
    port->base.on_destroy = &mixer_on_destroy;
    port->last_frame_type = PJMEDIA_FRAME_TYPE_NONE;
    port->last_frame_size = 0;
    port->last_frame_timestamp.u64 = 0;
    port->buffer = (pj_int16_t*) pj_pool_calloc(pool, samples_per_frame, sizeof(pj_int16_t));
    port->buffer_size = sizeof(pj_int16_t) * samples_per_frame;

    *p_port = &port->base;

    return PJ_SUCCESS;
}



/*
 * Put frame to file.
 */
static pj_status_t mixer_put_frame(pjmedia_port *this_port, pjmedia_frame *frame)
{
    struct mixer_port* port = (struct mixer_port*) this_port;

    if (!frame->size || frame->type != PJMEDIA_FRAME_TYPE_AUDIO) {
        port->last_frame_type = PJMEDIA_FRAME_TYPE_NONE;
        port->last_frame_size = 0;
        port->last_frame_timestamp.u64 = 0;
        return PJ_SUCCESS;
    }

    PJ_ASSERT_RETURN(frame->size <= port->buffer_size, PJ_EINVAL);

    port->last_frame_type = frame->type;
    pj_get_timestamp(&port->last_frame_timestamp);
    port->last_frame_size = MIN(port->buffer_size, frame->size);
    memcpy(port->buffer, frame->buf, port->last_frame_size);

    return PJ_SUCCESS;
}


/*
 * Get frame from file.
 */
static pj_status_t mixer_get_frame(pjmedia_port *this_port, pjmedia_frame *frame)
{
    struct mixer_port* port = (struct mixer_port*) this_port;
    pj_timestamp now;
    pj_uint32_t frame_age;

    pj_get_timestamp(&now);
    frame_age = pj_elapsed_usec(&port->last_frame_timestamp, &now);

    if (port->last_frame_timestamp.u64 != 0 && frame_age <= 100000) {
        frame->type = port->last_frame_type;
        frame->size = port->last_frame_size;
        frame->timestamp.u64 = 0;
        if (port->last_frame_size > 0) {
            memcpy(frame->buf, port->buffer, port->last_frame_size);
        }
    } else {
        frame->type = PJMEDIA_FRAME_TYPE_NONE;
        frame->size = 0;
        frame->timestamp.u64 = 0;
    }

    return PJ_SUCCESS;
}


/*
 * Destroy port.
 */
static pj_status_t mixer_on_destroy(pjmedia_port *this_port)
{
    return PJ_SUCCESS;
}


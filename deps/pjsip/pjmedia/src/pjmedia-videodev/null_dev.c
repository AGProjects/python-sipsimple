/* $Id: colorbar_dev.c 4158 2012-06-06 09:56:14Z nanang $ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
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
#include <pjmedia-videodev/videodev_imp.h>
#include <pj/assert.h>
#include <pj/log.h>
#include <pj/os.h>


#if defined(PJMEDIA_HAS_VIDEO) && PJMEDIA_HAS_VIDEO != 0 && \
    defined(PJMEDIA_VIDEO_DEV_HAS_NULL) && \
    PJMEDIA_VIDEO_DEV_HAS_NULL != 0


#define THIS_FILE		"null_dev.c"
#define DEFAULT_CLOCK_RATE	90000
#define DEFAULT_WIDTH		640
#define DEFAULT_HEIGHT		480
#define DEFAULT_FPS		5

/* null_ device info */
struct null_dev_info
{
    pjmedia_vid_dev_info	 info;
};

/* null_ factory */
struct null_factory
{
    pjmedia_vid_dev_factory	 base;
    pj_pool_t			*pool;
    pj_pool_factory		*pf;

    unsigned			 dev_count;
    struct null_dev_info	*dev_info;
};

struct null_fmt_info {
    pjmedia_format_id            fmt_id;        /* Format ID                */
};

/* Null video source supports */
static struct null_fmt_info null_fmts[] =
{
    { PJMEDIA_FORMAT_BGRA },
};

/* Video stream. */
struct null_stream
{
    pjmedia_vid_dev_stream	     base;	    /**< Base stream	    */
    pjmedia_vid_dev_param	     param;	    /**< Settings	    */
    pj_pool_t			    *pool;          /**< Memory pool.       */

    pjmedia_vid_dev_cb		     vid_cb;	    /**< Stream callback.   */
    void			    *user_data;	    /**< Application data.  */

    const struct null_fmt_info      *cbfi;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param    vafp;
    pj_uint8_t                      *first_line[PJMEDIA_MAX_VIDEO_PLANES];
    pj_timestamp		     ts;
    unsigned			     ts_inc;
};


/* Prototypes */
static pj_status_t null_factory_init(pjmedia_vid_dev_factory *f);
static pj_status_t null_factory_destroy(pjmedia_vid_dev_factory *f);
static pj_status_t null_factory_refresh(pjmedia_vid_dev_factory *f); 
static unsigned    null_factory_get_dev_count(pjmedia_vid_dev_factory *f);
static pj_status_t null_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					     unsigned index,
					     pjmedia_vid_dev_info *info);
static pj_status_t null_factory_default_param(pj_pool_t *pool,
                                              pjmedia_vid_dev_factory *f,
					      unsigned index,
					      pjmedia_vid_dev_param *param);
static pj_status_t null_factory_create_stream(
					pjmedia_vid_dev_factory *f,
					pjmedia_vid_dev_param *param,
					const pjmedia_vid_dev_cb *cb,
					void *user_data,
					pjmedia_vid_dev_stream **p_vid_strm);

static pj_status_t null_stream_get_param(pjmedia_vid_dev_stream *strm,
					 pjmedia_vid_dev_param *param);
static pj_status_t null_stream_get_cap(pjmedia_vid_dev_stream *strm,
				       pjmedia_vid_dev_cap cap,
				       void *value);
static pj_status_t null_stream_set_cap(pjmedia_vid_dev_stream *strm,
				       pjmedia_vid_dev_cap cap,
				       const void *value);
static pj_status_t null_stream_get_frame(pjmedia_vid_dev_stream *strm,
                                         pjmedia_frame *frame);
static pj_status_t null_stream_start(pjmedia_vid_dev_stream *strm);
static pj_status_t null_stream_stop(pjmedia_vid_dev_stream *strm);
static pj_status_t null_stream_destroy(pjmedia_vid_dev_stream *strm);

/* Operations */
static pjmedia_vid_dev_factory_op factory_op =
{
    &null_factory_init,
    &null_factory_destroy,
    &null_factory_get_dev_count,
    &null_factory_get_dev_info,
    &null_factory_default_param,
    &null_factory_create_stream,
    &null_factory_refresh
};

static pjmedia_vid_dev_stream_op stream_op =
{
    &null_stream_get_param,
    &null_stream_get_cap,
    &null_stream_set_cap,
    &null_stream_start,
    &null_stream_get_frame,
    NULL,
    &null_stream_stop,
    &null_stream_destroy
};


/****************************************************************************
 * Factory operations
 */
/*
 * Init null_ video driver.
 */
pjmedia_vid_dev_factory* pjmedia_null_factory(pj_pool_factory *pf)
{
    struct null_factory *f;
    pj_pool_t *pool;

    pool = pj_pool_create(pf, "null video", 512, 512, NULL);
    f = PJ_POOL_ZALLOC_T(pool, struct null_factory);
    f->pf = pf;
    f->pool = pool;
    f->base.op = &factory_op;

    return &f->base;
}


/* API: init factory */
static pj_status_t null_factory_init(pjmedia_vid_dev_factory *f)
{
    struct null_factory *cf = (struct null_factory*)f;
    struct null_dev_info *ddi;
    unsigned i;

    cf->dev_count = 1;
    cf->dev_info = (struct null_dev_info*)
 		   pj_pool_calloc(cf->pool, cf->dev_count,
 				  sizeof(struct null_dev_info));

    ddi = &cf->dev_info[0];
    pj_bzero(ddi, sizeof(*ddi));
    pj_ansi_strncpy(ddi->info.name, "Null video device",
		    sizeof(ddi->info.name));
    ddi->info.driver[sizeof(ddi->info.driver)-1] = '\0';
    pj_ansi_strncpy(ddi->info.driver, "Null", sizeof(ddi->info.driver));
    ddi->info.driver[sizeof(ddi->info.driver)-1] = '\0';
    ddi->info.dir = PJMEDIA_DIR_CAPTURE;
    ddi->info.has_callback = PJ_FALSE;

    ddi->info.caps = PJMEDIA_VID_DEV_CAP_FORMAT;
    ddi->info.fmt_cnt = sizeof(null_fmts)/sizeof(null_fmts[0]);
    for (i = 0; i < ddi->info.fmt_cnt; i++) {
        pjmedia_format *fmt = &ddi->info.fmt[i];
        pjmedia_format_init_video(fmt, null_fmts[i].fmt_id,
				  DEFAULT_WIDTH, DEFAULT_HEIGHT,
				  DEFAULT_FPS, 1);
    }

    PJ_LOG(4, (THIS_FILE, "Null video src initialized with %d device(s):", cf->dev_count));
    for (i = 0; i < cf->dev_count; i++) {
	PJ_LOG(4, (THIS_FILE, "%2d: %s", i, cf->dev_info[i].info.name));
    }

    return PJ_SUCCESS;
}

/* API: destroy factory */
static pj_status_t null_factory_destroy(pjmedia_vid_dev_factory *f)
{
    struct null_factory *cf = (struct null_factory*)f;
    pj_pool_t *pool = cf->pool;

    cf->pool = NULL;
    pj_pool_release(pool);

    return PJ_SUCCESS;
}

/* API: refresh the list of devices */
static pj_status_t null_factory_refresh(pjmedia_vid_dev_factory *f)
{
    PJ_UNUSED_ARG(f);
    return PJ_SUCCESS;
}

/* API: get number of devices */
static unsigned null_factory_get_dev_count(pjmedia_vid_dev_factory *f)
{
    struct null_factory *cf = (struct null_factory*)f;
    return cf->dev_count;
}

/* API: get device info */
static pj_status_t null_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					     unsigned index,
					     pjmedia_vid_dev_info *info)
{
    struct null_factory *cf = (struct null_factory*)f;

    PJ_ASSERT_RETURN(index < cf->dev_count, PJMEDIA_EVID_INVDEV);

    pj_memcpy(info, &cf->dev_info[index].info, sizeof(*info));

    return PJ_SUCCESS;
}

/* API: create default device parameter */
static pj_status_t null_factory_default_param(pj_pool_t *pool,
                                              pjmedia_vid_dev_factory *f,
					      unsigned index,
					      pjmedia_vid_dev_param *param)
{
    struct null_factory *cf = (struct null_factory*)f;
    struct null_dev_info *di = &cf->dev_info[index];

    PJ_ASSERT_RETURN(index < cf->dev_count, PJMEDIA_EVID_INVDEV);

    PJ_UNUSED_ARG(pool);

    pj_bzero(param, sizeof(*param));
    param->dir = PJMEDIA_DIR_CAPTURE;
    param->cap_id = index;
    param->rend_id = PJMEDIA_VID_INVALID_DEV;
    param->flags = PJMEDIA_VID_DEV_CAP_FORMAT;
    param->clock_rate = DEFAULT_CLOCK_RATE;
    pj_memcpy(&param->fmt, &di->info.fmt[0], sizeof(param->fmt));

    return PJ_SUCCESS;
}

static const struct null_fmt_info* get_null_fmt_info(pjmedia_format_id id)
{
    unsigned i;

    for (i = 0; i < sizeof(null_fmts)/sizeof(null_fmts[0]); i++) {
        if (null_fmts[i].fmt_id == id)
            return &null_fmts[i];
    }

    return NULL;
}


/* API: create stream */
static pj_status_t null_factory_create_stream(
					pjmedia_vid_dev_factory *f,
					pjmedia_vid_dev_param *param,
					const pjmedia_vid_dev_cb *cb,
					void *user_data,
					pjmedia_vid_dev_stream **p_vid_strm)
{
    struct null_factory *cf = (struct null_factory*)f;
    pj_pool_t *pool;
    struct null_stream *strm;
    const pjmedia_video_format_detail *vfd;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param vafp;
    const struct null_fmt_info *cbfi;
    unsigned i;

    PJ_ASSERT_RETURN(f && param && p_vid_strm, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->fmt.type == PJMEDIA_TYPE_VIDEO &&
		     param->fmt.detail_type == PJMEDIA_FORMAT_DETAIL_VIDEO &&
                     param->dir == PJMEDIA_DIR_CAPTURE,
		     PJ_EINVAL);

    pj_bzero(&vafp, sizeof(vafp));

    vfd = pjmedia_format_get_video_format_detail(&param->fmt, PJ_TRUE);
    vfi = pjmedia_get_video_format_info(NULL, param->fmt.id);
    cbfi = get_null_fmt_info(param->fmt.id);
    if (!vfi || !cbfi)
        return PJMEDIA_EVID_BADFORMAT;

    vafp.size = param->fmt.det.vid.size;
    if (vfi->apply_fmt(vfi, &vafp) != PJ_SUCCESS)
        return PJMEDIA_EVID_BADFORMAT;

    /* Create and Initialize stream descriptor */
    pool = pj_pool_create(cf->pf, "null-dev", 512, 512, NULL);
    PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

    strm = PJ_POOL_ZALLOC_T(pool, struct null_stream);
    pj_memcpy(&strm->param, param, sizeof(*param));
    strm->pool = pool;
    pj_memcpy(&strm->vid_cb, cb, sizeof(*cb));
    strm->user_data = user_data;
    strm->vfi = vfi;
    strm->cbfi = cbfi;
    pj_memcpy(&strm->vafp, &vafp, sizeof(vafp));
    strm->ts_inc = PJMEDIA_SPF2(param->clock_rate, &vfd->fps, 1);

    for (i = 0; i < vfi->plane_cnt; ++i) {
        strm->first_line[i] = pj_pool_alloc(pool, vafp.strides[i]);
        pj_memset(strm->first_line[i], 0, vafp.strides[i]);
    }

    /* Done */
    strm->base.op = &stream_op;
    *p_vid_strm = &strm->base;

    return PJ_SUCCESS;
}

/* API: Get stream info. */
static pj_status_t null_stream_get_param(pjmedia_vid_dev_stream *s,
					 pjmedia_vid_dev_param *pi)
{
    struct null_stream *strm = (struct null_stream*)s;

    PJ_ASSERT_RETURN(strm && pi, PJ_EINVAL);

    pj_memcpy(pi, &strm->param, sizeof(*pi));
    return PJ_SUCCESS;
}

/* API: get capability */
static pj_status_t null_stream_get_cap(pjmedia_vid_dev_stream *s,
				       pjmedia_vid_dev_cap cap,
				       void *pval)
{
    struct null_stream *strm = (struct null_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);
    return PJMEDIA_EVID_INVCAP;
}

/* API: set capability */
static pj_status_t null_stream_set_cap(pjmedia_vid_dev_stream *s,
				       pjmedia_vid_dev_cap cap,
				       const void *pval)
{
    struct null_stream *strm = (struct null_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);
    return PJMEDIA_EVID_INVCAP;
}


/* API: Get frame from stream */
static pj_status_t null_stream_get_frame(pjmedia_vid_dev_stream *strm,
                                         pjmedia_frame *frame)
{
    struct null_stream *stream = (struct null_stream*)strm;
    unsigned i;
    pj_uint8_t *ptr = frame->buf;

    frame->type = PJMEDIA_FRAME_TYPE_VIDEO;
    frame->bit_info = 0;
    frame->timestamp = stream->ts;
    stream->ts.u64 += stream->ts_inc;

    /* paint subsequent lines */
    for (i=0; i<stream->vfi->plane_cnt; ++i) {
        pj_uint8_t *plane_end;
        plane_end = ptr + stream->vafp.plane_bytes[i];
        while (ptr < plane_end) {
            pj_memcpy(ptr, stream->first_line[i], stream->vafp.strides[i]);
            ptr += stream->vafp.strides[i];
        }
    }

    return PJ_SUCCESS;
}

/* API: Start stream. */
static pj_status_t null_stream_start(pjmedia_vid_dev_stream *strm)
{
    struct null_stream *stream = (struct null_stream*)strm;

    PJ_UNUSED_ARG(stream);

    PJ_LOG(4, (THIS_FILE, "Starting null video stream"));

    return PJ_SUCCESS;
}

/* API: Stop stream. */
static pj_status_t null_stream_stop(pjmedia_vid_dev_stream *strm)
{
    struct null_stream *stream = (struct null_stream*)strm;

    PJ_UNUSED_ARG(stream);

    PJ_LOG(4, (THIS_FILE, "Stopping null video stream"));

    return PJ_SUCCESS;
}


/* API: Destroy stream. */
static pj_status_t null_stream_destroy(pjmedia_vid_dev_stream *strm)
{
    struct null_stream *stream = (struct null_stream*)strm;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);

    null_stream_stop(strm);

    pj_pool_release(stream->pool);

    return PJ_SUCCESS;
}

#endif	/* PJMEDIA_VIDEO_DEV_HAS_NULL */

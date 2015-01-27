/*
 * Copyright (C) 2014-present AG Projects
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
    defined(PJMEDIA_VIDEO_DEV_HAS_FB) && PJMEDIA_VIDEO_DEV_HAS_FB != 0

#include <pjmedia-videodev/fb_dev.h>

#define THIS_FILE		"fb_dev.c"
#define DEFAULT_CLOCK_RATE	90000
#define DEFAULT_WIDTH		640
#define DEFAULT_HEIGHT		480
#define DEFAULT_FPS		25


/* Supported formats */
#if defined(PJ_DARWINOS) && PJ_DARWINOS!=0
static pjmedia_format_id fb_fmts[] = {PJMEDIA_FORMAT_ARGB};
#else
static pjmedia_format_id fb_fmts[] = {PJMEDIA_FORMAT_BGRA};
#endif


/* fb device info */
struct fb_dev_info
{
    pjmedia_vid_dev_info	 info;
};


/* factory */
struct fb_factory
{
    pjmedia_vid_dev_factory	 base;
    pj_pool_t			*pool;
    pj_pool_factory		*pf;

    unsigned			 dev_count;
    struct fb_dev_info	        *dev_info;
};


/* Video stream. */
struct fb_stream
{
    pjmedia_vid_dev_stream	 base;		    /**< Base stream	    */
    pjmedia_vid_dev_param	 param;		    /**< Settings	    */
    pj_pool_t			*pool;              /**< Memory pool.       */

    pjmedia_vid_dev_cb		 vid_cb;            /**< Stream callback.   */
    void			*user_data;         /**< Application data.  */

    struct fb_factory           *ff;
    pj_bool_t			 is_running;
    pjmedia_rect_size            vid_size;

    struct {
        pjmedia_vid_dev_fb_frame_cb cb;
        void *user_data;
    } frame_handler;
};


/* Prototypes */
static pj_status_t fb_factory_init(pjmedia_vid_dev_factory *f);
static pj_status_t fb_factory_destroy(pjmedia_vid_dev_factory *f);
static pj_status_t fb_factory_refresh(pjmedia_vid_dev_factory *f);
static unsigned    fb_factory_get_dev_count(pjmedia_vid_dev_factory *f);
static pj_status_t fb_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					   unsigned index,
					   pjmedia_vid_dev_info *info);
static pj_status_t fb_factory_default_param(pj_pool_t *pool,
                                            pjmedia_vid_dev_factory *f,
					    unsigned index,
					    pjmedia_vid_dev_param *param);
static pj_status_t fb_factory_create_stream(pjmedia_vid_dev_factory *f,
					    pjmedia_vid_dev_param *param,
					    const pjmedia_vid_dev_cb *cb,
					    void *user_data,
					    pjmedia_vid_dev_stream **p_vid_strm);

static pj_status_t fb_stream_get_param(pjmedia_vid_dev_stream *strm,
				       pjmedia_vid_dev_param *param);
static pj_status_t fb_stream_get_cap(pjmedia_vid_dev_stream *strm,
				     pjmedia_vid_dev_cap cap,
				     void *value);
static pj_status_t fb_stream_set_cap(pjmedia_vid_dev_stream *strm,
				     pjmedia_vid_dev_cap cap,
				     const void *value);
static pj_status_t fb_stream_put_frame(pjmedia_vid_dev_stream *strm,
                                       const pjmedia_frame *frame);
static pj_status_t fb_stream_start(pjmedia_vid_dev_stream *strm);
static pj_status_t fb_stream_stop(pjmedia_vid_dev_stream *strm);
static pj_status_t fb_stream_destroy(pjmedia_vid_dev_stream *strm);


/* Operations */
static pjmedia_vid_dev_factory_op factory_op =
{
    &fb_factory_init,
    &fb_factory_destroy,
    &fb_factory_get_dev_count,
    &fb_factory_get_dev_info,
    &fb_factory_default_param,
    &fb_factory_create_stream,
    &fb_factory_refresh
};

static pjmedia_vid_dev_stream_op stream_op =
{
    &fb_stream_get_param,
    &fb_stream_get_cap,
    &fb_stream_set_cap,
    &fb_stream_start,
    NULL,
    &fb_stream_put_frame,
    &fb_stream_stop,
    &fb_stream_destroy
};


/****************************************************************************
 * Factory operations
 */
/*
 * Init FB video driver.
 */
pjmedia_vid_dev_factory* pjmedia_fb_factory(pj_pool_factory *pf)
{
    struct fb_factory *f;
    pj_pool_t *pool;

    pool = pj_pool_create(pf, "fb video", 1000, 1000, NULL);
    f = PJ_POOL_ZALLOC_T(pool, struct fb_factory);
    f->pf = pf;
    f->pool = pool;
    f->base.op = &factory_op;

    return &f->base;
}


/* API: init factory */
static pj_status_t fb_factory_init(pjmedia_vid_dev_factory *f)
{
    struct fb_factory *ff = (struct fb_factory*)f;
    struct fb_dev_info *di;
    unsigned i, l;

    /* Initialize input and output devices here */
    ff->dev_info = (struct fb_dev_info*)
    pj_pool_calloc(ff->pool, 1, sizeof(struct fb_dev_info));

    ff->dev_count = 0;
    di = &ff->dev_info[ff->dev_count++];
    pj_bzero(di, sizeof(*di));
    strcpy(di->info.name, "FrameBuffer renderer");
    strcpy(di->info.driver, "FrameBuffer");
    di->info.dir = PJMEDIA_DIR_RENDER;
    di->info.has_callback = PJ_FALSE;
    di->info.caps = 0;

    for (i = 0; i < ff->dev_count; i++) {
	di = &ff->dev_info[i];
	di->info.fmt_cnt = PJ_ARRAY_SIZE(fb_fmts);
	di->info.caps |= PJMEDIA_VID_DEV_CAP_FORMAT;

	for (l = 0; l < PJ_ARRAY_SIZE(fb_fmts); l++) {
	    pjmedia_format *fmt = &di->info.fmt[l];
	    pjmedia_format_init_video(fmt,
				      fb_fmts[l],
				      DEFAULT_WIDTH,
				      DEFAULT_HEIGHT,
				      DEFAULT_FPS, 1);
	}
    }

    PJ_LOG(4, (THIS_FILE, "FrameBuffer initialized"));

    return PJ_SUCCESS;
}


/* API: destroy factory */
static pj_status_t fb_factory_destroy(pjmedia_vid_dev_factory *f)
{
    struct fb_factory *ff = (struct fb_factory*)f;
    pj_pool_t *pool = ff->pool;

    ff->pool = NULL;
    pj_pool_release(pool);

    return PJ_SUCCESS;
}


/* API: refresh the list of devices */
static pj_status_t fb_factory_refresh(pjmedia_vid_dev_factory *f)
{
    PJ_UNUSED_ARG(f);
    return PJ_SUCCESS;
}


/* API: get number of devices */
static unsigned fb_factory_get_dev_count(pjmedia_vid_dev_factory *f)
{
    struct fb_factory *ff = (struct fb_factory*)f;
    return ff->dev_count;
}


/* API: get device info */
static pj_status_t fb_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					   unsigned index,
					   pjmedia_vid_dev_info *info)
{
    struct fb_factory *ff = (struct fb_factory*)f;

    PJ_ASSERT_RETURN(index < ff->dev_count, PJMEDIA_EVID_INVDEV);
    pj_memcpy(info, &ff->dev_info[index].info, sizeof(*info));

    return PJ_SUCCESS;
}


/* API: create default device parameter */
static pj_status_t fb_factory_default_param(pj_pool_t *pool,
                                            pjmedia_vid_dev_factory *f,
					    unsigned index,
					    pjmedia_vid_dev_param *param)
{
    struct fb_factory *ff = (struct fb_factory*)f;
    struct fb_dev_info *di = &ff->dev_info[index];

    PJ_ASSERT_RETURN(index < ff->dev_count, PJMEDIA_EVID_INVDEV);
    PJ_UNUSED_ARG(pool);

    pj_bzero(param, sizeof(*param));
    param->dir = PJMEDIA_DIR_RENDER;
    param->rend_id = index;
    param->cap_id = PJMEDIA_VID_INVALID_DEV;

    /* Set the device capabilities here */
    param->flags = PJMEDIA_VID_DEV_CAP_FORMAT;
    param->clock_rate = DEFAULT_CLOCK_RATE;
    pj_memcpy(&param->fmt, &di->info.fmt[0], sizeof(param->fmt));

    return PJ_SUCCESS;
}


/* API: Put frame from stream */
static pj_status_t fb_stream_put_frame(pjmedia_vid_dev_stream *strm,
                                       const pjmedia_frame *frame)
{
    struct fb_stream *stream = (struct fb_stream*)strm;

    if (!stream->is_running)
	return PJ_EINVALIDOP;

    if (frame->size==0 || frame->buf==NULL)
	return PJ_SUCCESS;

    if (stream->frame_handler.cb)
        stream->frame_handler.cb(frame, stream->vid_size, stream->frame_handler.user_data);

    return PJ_SUCCESS;
}

/* API: create stream */
static pj_status_t fb_factory_create_stream(pjmedia_vid_dev_factory *f,
					    pjmedia_vid_dev_param *param,
					    const pjmedia_vid_dev_cb *cb,
					    void *user_data,
					    pjmedia_vid_dev_stream **p_vid_strm)
{
    struct fb_factory *ff = (struct fb_factory*)f;
    pj_pool_t *pool;
    pj_status_t status;
    struct fb_stream *strm;
    const pjmedia_video_format_info *vfi;

    PJ_ASSERT_RETURN(f && param && p_vid_strm, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->dir == PJMEDIA_DIR_RENDER, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->fmt.type == PJMEDIA_TYPE_VIDEO &&
		     param->fmt.detail_type == PJMEDIA_FORMAT_DETAIL_VIDEO &&
                     param->dir == PJMEDIA_DIR_RENDER,
		     PJ_EINVAL);

    vfi = pjmedia_get_video_format_info(NULL, param->fmt.id);
    if (!vfi)
        return PJMEDIA_EVID_BADFORMAT;

    /* Create and Initialize stream descriptor */
    pool = pj_pool_create(ff->pf, "fb-dev", 1000, 1000, NULL);
    PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

    strm = PJ_POOL_ZALLOC_T(pool, struct fb_stream);
    pj_memcpy(&strm->param, param, sizeof(*param));
    strm->pool = pool;
    strm->ff = ff;
    pj_memcpy(&strm->vid_cb, cb, sizeof(*cb));
    strm->user_data = user_data;

    status = fb_stream_set_cap(&strm->base, PJMEDIA_VID_DEV_CAP_FORMAT, &param->fmt);
    if (status != PJ_SUCCESS) {
        fb_stream_destroy((pjmedia_vid_dev_stream *)strm);
        return status;
    }

    /* Done */
    strm->base.op = &stream_op;
    *p_vid_strm = &strm->base;

    return PJ_SUCCESS;
}


/* API: Get stream info. */
static pj_status_t fb_stream_get_param(pjmedia_vid_dev_stream *s,
			               pjmedia_vid_dev_param *pi)
{
    struct fb_stream *strm = (struct fb_stream*)s;
    PJ_ASSERT_RETURN(strm && pi, PJ_EINVAL);

    pj_memcpy(pi, &strm->param, sizeof(*pi));

    return PJ_SUCCESS;
}


/* API: get capability */
static pj_status_t fb_stream_get_cap(pjmedia_vid_dev_stream *s,
				     pjmedia_vid_dev_cap cap,
				     void *pval)
{
    struct fb_stream *strm = (struct fb_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_UNUSED_ARG(cap);
    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    return PJMEDIA_EVID_INVCAP;
}


/* API: set capability */
static pj_status_t fb_stream_set_cap(pjmedia_vid_dev_stream *s,
				     pjmedia_vid_dev_cap cap,
				     const void *pval)
{
    struct fb_stream *strm = (struct fb_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    if (cap == PJMEDIA_VID_DEV_CAP_FORMAT) {
        const pjmedia_video_format_info *vfi;
        pjmedia_video_format_detail *vfd;
        pjmedia_format *fmt = (pjmedia_format *)pval;

        vfi = pjmedia_get_video_format_info(pjmedia_video_format_mgr_instance(), fmt->id);
        if (!vfi)
            return PJMEDIA_EVID_BADFORMAT;

        pjmedia_format_copy(&strm->param.fmt, fmt);

        vfd = pjmedia_format_get_video_format_detail(fmt, PJ_TRUE);
        pj_memcpy(&strm->vid_size, &vfd->size, sizeof(vfd->size));
        if (strm->param.disp_size.w == 0 || strm->param.disp_size.h == 0)
            pj_memcpy(&strm->param.disp_size, &vfd->size, sizeof(vfd->size));

        return PJ_SUCCESS;
    }

    return PJMEDIA_EVID_INVCAP;
}


/* API: Start stream. */
static pj_status_t fb_stream_start(pjmedia_vid_dev_stream *strm)
{
    struct fb_stream *stream = (struct fb_stream*)strm;
    PJ_UNUSED_ARG(strm);

    PJ_LOG(4, (THIS_FILE, "Starting FB video stream"));
    stream->is_running = PJ_TRUE;

    return PJ_SUCCESS;
}


/* API: Stop stream. */
static pj_status_t fb_stream_stop(pjmedia_vid_dev_stream *strm)
{
    struct fb_stream *stream = (struct fb_stream*)strm;
    PJ_UNUSED_ARG(strm);

    PJ_LOG(4, (THIS_FILE, "Stopping FB video stream"));
    stream->is_running = PJ_FALSE;

    return PJ_SUCCESS;
}


/* API: Destroy stream. */
static pj_status_t fb_stream_destroy(pjmedia_vid_dev_stream *strm)
{
    struct fb_stream *stream = (struct fb_stream*)strm;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);

    fb_stream_stop(strm);
    pj_pool_release(stream->pool);

    return PJ_SUCCESS;
}


/* API: set callback for handling frames */
pj_status_t
pjmedia_vid_dev_fb_set_callback(pjmedia_vid_dev_stream *strm,
                                pjmedia_vid_dev_fb_frame_cb cb,
                                void *user_data)
{
    struct fb_stream *stream = (struct fb_stream*)strm;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);
    if (stream->is_running)
        return PJ_EBUSY;

    stream->frame_handler.cb = cb;
    stream->frame_handler.user_data = user_data;

    return PJ_SUCCESS;
}

#endif	/* PJMEDIA_VIDEO_DEV_HAS_FB */

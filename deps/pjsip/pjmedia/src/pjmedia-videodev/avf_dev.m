/*
 * Copyright (C) 2014-present AG Projects (http://ag-projects.com)
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
    defined(PJMEDIA_VIDEO_DEV_HAS_AVF) && PJMEDIA_VIDEO_DEV_HAS_AVF != 0

#include <Foundation/NSAutoreleasePool.h>
#include <AVFoundation/AVFoundation.h>
#include <QuartzCore/QuartzCore.h>
#include <dispatch/dispatch.h>

#define THIS_FILE		"avf_dev.c"
#define DEFAULT_CLOCK_RATE	90000
#define DEFAULT_WIDTH		640
#define DEFAULT_HEIGHT		480
#define DEFAULT_FPS		15


typedef struct avf_fmt_info
{
    pjmedia_format_id   pjmedia_format;
    unsigned		avf_format;
} avf_fmt_info;

static avf_fmt_info avf_fmts[] =
{
    {PJMEDIA_FORMAT_BGRA, kCVPixelFormatType_32BGRA},
    {PJMEDIA_FORMAT_YUY2, kCVPixelFormatType_422YpCbCr8_yuvs},
    {PJMEDIA_FORMAT_UYVY, kCVPixelFormatType_422YpCbCr8},
};

/* avf device info */
struct avf_dev_info
{
    pjmedia_vid_dev_info	 info;
    AVCaptureDevice              *dev;
};

/* avf factory */
struct avf_factory
{
    pjmedia_vid_dev_factory	 base;
    pj_pool_t			*pool;
    pj_pool_t			*dev_pool;
    pj_pool_factory		*pf;

    unsigned			 dev_count;
    struct avf_dev_info		*dev_info;
};

struct avf_stream;    /* forward declaration */
typedef void (*func_ptr)(struct avf_stream *strm);

@interface AVFDelegate: NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
{
@public
    struct avf_stream *stream;
}
@end


/* Video stream. */
struct avf_stream
{
    pjmedia_vid_dev_stream  base;	    /**< Base stream	       */
    pjmedia_vid_dev_param   param;	    /**< Settings	       */
    pj_pool_t		   *pool;           /**< Memory pool.          */

    pj_timestamp	    cap_frame_ts;   /**< Captured frame tstamp */
    unsigned		    cap_ts_inc;	    /**< Increment	       */

    pjmedia_vid_dev_cb	    vid_cb;         /**< Stream callback.      */
    void		   *user_data;      /**< Application data.     */

    pjmedia_rect_size	    size;

    pj_bool_t		    cap_thread_initialized;
    pj_thread_desc	    cap_thread_desc;
    pj_thread_t		   *cap_thread;
    pj_bool_t               cap_exited;

    struct avf_factory      *af;
    pj_status_t             status;
    pj_bool_t               is_running;

    dispatch_queue_t                    video_ops_queue;

    AVCaptureSession			*cap_session;
    AVCaptureDeviceInput		*dev_input;
    AVCaptureVideoDataOutput	        *video_output;
    AVFDelegate                         *delegate;
};


/* Prototypes */
static pj_status_t avf_factory_init(pjmedia_vid_dev_factory *f);
static pj_status_t avf_factory_destroy(pjmedia_vid_dev_factory *f);
static pj_status_t avf_factory_refresh(pjmedia_vid_dev_factory *f);
static unsigned    avf_factory_get_dev_count(pjmedia_vid_dev_factory *f);
static pj_status_t avf_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					   unsigned index,
					   pjmedia_vid_dev_info *info);
static pj_status_t avf_factory_default_param(pj_pool_t *pool,
					    pjmedia_vid_dev_factory *f,
					    unsigned index,
					    pjmedia_vid_dev_param *param);
static pj_status_t avf_factory_create_stream(pjmedia_vid_dev_factory *f,
					     pjmedia_vid_dev_param *param,
					     const pjmedia_vid_dev_cb *cb,
					     void *user_data,
					     pjmedia_vid_dev_stream **p_vid_strm);

static pj_status_t avf_stream_get_param(pjmedia_vid_dev_stream *strm,
				        pjmedia_vid_dev_param *param);
static pj_status_t avf_stream_get_cap(pjmedia_vid_dev_stream *strm,
				      pjmedia_vid_dev_cap cap,
				      void *value);
static pj_status_t avf_stream_set_cap(pjmedia_vid_dev_stream *strm,
				      pjmedia_vid_dev_cap cap,
				      const void *value);
static pj_status_t avf_stream_start(pjmedia_vid_dev_stream *strm);
static pj_status_t avf_stream_stop(pjmedia_vid_dev_stream *strm);
static pj_status_t avf_stream_destroy(pjmedia_vid_dev_stream *strm);

/* Operations */
static pjmedia_vid_dev_factory_op factory_op =
{
    &avf_factory_init,
    &avf_factory_destroy,
    &avf_factory_get_dev_count,
    &avf_factory_get_dev_info,
    &avf_factory_default_param,
    &avf_factory_create_stream,
    &avf_factory_refresh
};

static pjmedia_vid_dev_stream_op stream_op =
{
    &avf_stream_get_param,
    &avf_stream_get_cap,
    &avf_stream_set_cap,
    &avf_stream_start,
    NULL,
    NULL,
    &avf_stream_stop,
    &avf_stream_destroy
};


/****************************************************************************
 * Factory operations
 */
/*
 * Init avf video driver.
 */
pjmedia_vid_dev_factory* pjmedia_avf_factory(pj_pool_factory *pf)
{
    struct avf_factory *f;
    pj_pool_t *pool;

    pool = pj_pool_create(pf, "avf video", 4000, 4000, NULL);
    f = PJ_POOL_ZALLOC_T(pool, struct avf_factory);
    f->pf = pf;
    f->pool = pool;
    f->base.op = &factory_op;

    return &f->base;
}


/* API: init factory */
static pj_status_t avf_factory_init(pjmedia_vid_dev_factory *f)
{
    return avf_factory_refresh(f);
}

/* API: destroy factory */
static pj_status_t avf_factory_destroy(pjmedia_vid_dev_factory *f)
{
    struct avf_factory *af = (struct avf_factory*)f;
    pj_pool_t *pool = af->pool;

    if (af->dev_pool)
        pj_pool_release(af->dev_pool);
    af->pool = NULL;
    if (pool)
        pj_pool_release(pool);

    return PJ_SUCCESS;
}

/* API: refresh the list of devices */
static pj_status_t avf_factory_refresh(pjmedia_vid_dev_factory *f)
{
    struct avf_factory *af = (struct avf_factory*)f;
    struct avf_dev_info *di;
    unsigned dev_count = 0;
    NSAutoreleasePool *apool = [[NSAutoreleasePool alloc]init];
    NSArray *dev_array;

    if (af->dev_pool) {
        pj_pool_release(af->dev_pool);
        af->dev_pool = NULL;
    }

    dev_array = [AVCaptureDevice devices];
    for (AVCaptureDevice *device in dev_array) {
	if ([device hasMediaType:AVMediaTypeVideo] && ![device isSuspended]) {
	    dev_count++;
	}
    }

    /* Initialize input and output devices here */
    af->dev_count = 0;
    af->dev_pool = pj_pool_create(af->pf, "avf video", 500, 500, NULL);

    af->dev_info = (struct avf_dev_info*) pj_pool_calloc(af->dev_pool, dev_count, sizeof(struct avf_dev_info));
    for (AVCaptureDevice *device in dev_array) {
	if (![device hasMediaType:AVMediaTypeVideo] || [device isSuspended]) {
	    continue;
	}

        di = &af->dev_info[af->dev_count++];
        pj_bzero(di, sizeof(*di));
        di->dev = device;
        pj_ansi_strncpy(di->info.name, [device.localizedName UTF8String], sizeof(di->info.name));
        pj_ansi_strncpy(di->info.driver, "AVF", sizeof(di->info.driver));
        di->info.dir = PJMEDIA_DIR_CAPTURE;
        di->info.has_callback = PJ_TRUE;
        di->info.fmt_cnt = 0;
        di->info.caps = PJMEDIA_VID_DEV_CAP_FORMAT;

        PJ_LOG(4, (THIS_FILE, " dev: %s", di->info.name));

        for (AVCaptureDeviceFormat* f in [device formats]) {
            unsigned i;
            CMFormatDescriptionRef desc = [f formatDescription];
            for (i = 0; i < PJ_ARRAY_SIZE(avf_fmts); i++) {
                if (CMFormatDescriptionGetMediaSubType(desc) == avf_fmts[i].avf_format) {
                    char fmt_name[5];
                    CMVideoDimensions dim = CMVideoFormatDescriptionGetDimensions(desc);
                    if (dim.width < 640)
                        continue;
                    pjmedia_fourcc_name(avf_fmts[i].pjmedia_format, fmt_name);
                    PJ_LOG(4, (THIS_FILE, "  detected resolution %dx%d (%s)", dim.width, dim.height, fmt_name));
                    pjmedia_format *fmt = &di->info.fmt[di->info.fmt_cnt++];
                    pjmedia_format_init_video(fmt,
                                              avf_fmts[i].pjmedia_format,
                                              dim.width,
                                              dim.height,
                                              DEFAULT_FPS, 1);
                }
            }
        }

        if (di->info.fmt_cnt == 0) {
            PJ_LOG(4, (THIS_FILE, "  there are no compatible formats, using default"));
            pjmedia_format *fmt = &di->info.fmt[di->info.fmt_cnt++];
            pjmedia_format_init_video(fmt,
                                      avf_fmts[0].pjmedia_format,
                                      DEFAULT_WIDTH,
                                      DEFAULT_HEIGHT,
                                      DEFAULT_FPS, 1);
        }
    }

    [apool release];

    PJ_LOG(4, (THIS_FILE, "avf video has %d devices", af->dev_count));

    return PJ_SUCCESS;
}

/* API: get number of devices */
static unsigned avf_factory_get_dev_count(pjmedia_vid_dev_factory *f)
{
    struct avf_factory *af = (struct avf_factory*)f;
    return af->dev_count;
}

/* API: get device info */
static pj_status_t avf_factory_get_dev_info(pjmedia_vid_dev_factory *f,
					    unsigned index,
					    pjmedia_vid_dev_info *info)
{
    struct avf_factory *af = (struct avf_factory*)f;
    PJ_ASSERT_RETURN(index < af->dev_count, PJMEDIA_EVID_INVDEV);

    pj_memcpy(info, &af->dev_info[index].info, sizeof(*info));

    return PJ_SUCCESS;
}

/* API: create default device parameter */
static pj_status_t avf_factory_default_param(pj_pool_t *pool,
					     pjmedia_vid_dev_factory *f,
					     unsigned index,
					     pjmedia_vid_dev_param *param)
{
    struct avf_factory *af = (struct avf_factory*)f;
    struct avf_dev_info *di = &af->dev_info[index];

    PJ_ASSERT_RETURN(index < af->dev_count, PJMEDIA_EVID_INVDEV);
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

static avf_fmt_info* get_avf_format_info(pjmedia_format_id id)
{
    unsigned i;

    for (i = 0; i < PJ_ARRAY_SIZE(avf_fmts); i++) {
        if (avf_fmts[i].pjmedia_format == id)
            return &avf_fmts[i];
    }

    return NULL;
}


@implementation AVFDelegate
- (void)captureOutput:(AVCaptureOutput *)captureOutput
		      didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
		      fromConnection:(AVCaptureConnection *)connection
{
    pjmedia_frame frame = {0};
    CVImageBufferRef img;
    CVReturn ret;
    OSType type;
    size_t width, height;

    /* Register thread if needed */
    if (stream->cap_thread_initialized == 0 || !pj_thread_is_registered()) {
        pj_bzero(stream->cap_thread_desc, sizeof(pj_thread_desc));
        pj_thread_register("avf_cap", stream->cap_thread_desc, &stream->cap_thread);
        stream->cap_thread_initialized = 1;
    }

    if (!sampleBuffer)
	return;

    /* Get a CMSampleBuffer's Core Video image buffer for the media data */
    img = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!img)
        return;

    /* Check for supported formats */
    type = CVPixelBufferGetPixelFormatType(img);
    switch(type) {
        case kCVPixelFormatType_32BGRA:
        case kCVPixelFormatType_422YpCbCr8_yuvs:
        case kCVPixelFormatType_422YpCbCr8:
            break;
        default:
            PJ_LOG(4, (THIS_FILE, "Unsupported image format! %c%c%c%c", type>>24, type>>16, type>>8, type>>0));
            return;
    }

    /* Lock the base address of the pixel buffer */
    ret = CVPixelBufferLockBaseAddress(img, kCVPixelBufferLock_ReadOnly);
    if (ret != kCVReturnSuccess)
        return;

    width = CVPixelBufferGetWidth(img);
    height = CVPixelBufferGetHeight(img);

    /* Prepare frame */
    frame.type = PJMEDIA_FRAME_TYPE_VIDEO;
    frame.timestamp.u64 = stream->cap_frame_ts.u64;
    frame.buf = CVPixelBufferGetBaseAddress(img);
    frame.size = CVPixelBufferGetBytesPerRow(img) * height;

    if (stream->size.w != width || stream->size.h != height) {
        PJ_LOG(4, (THIS_FILE, "AVF image size changed, before: %dx%d, after: %dx%d", stream->size.w, stream->size.h, width, height));
    }

    if (stream->vid_cb.capture_cb) {
        (*stream->vid_cb.capture_cb)(&stream->base, stream->user_data, &frame);
    }

    stream->cap_frame_ts.u64 += stream->cap_ts_inc;

    /* Unlock the pixel buffer */
    CVPixelBufferUnlockBaseAddress(img, kCVPixelBufferLock_ReadOnly);
}
@end


static void init_avf_stream(struct avf_stream *strm)
{
    const pjmedia_video_format_info *vfi;
    pjmedia_video_format_detail *vfd;
    avf_fmt_info *fi = get_avf_format_info(strm->param.fmt.id);
    NSError *error;
    pj_status_t status;

    if (!fi) {
        strm->status = PJMEDIA_EVID_BADFORMAT;
        return;
    }

    strm->cap_session = [[AVCaptureSession alloc] init];
    if (!strm->cap_session) {
        strm->status = PJ_ENOMEM;
        return;
    }

    strm->cap_session.sessionPreset = AVCaptureSessionPresetHigh;
    vfd = pjmedia_format_get_video_format_detail(&strm->param.fmt, PJ_TRUE);
    pj_assert(vfd);
    vfi = pjmedia_get_video_format_info(NULL, strm->param.fmt.id);
    pj_assert(vfi);
    vfd->size = strm->size;

    PJ_LOG(4, (THIS_FILE, "Opening video device at %dx%d resolution", vfd->size.w, vfd->size.h));

    /* Add the video device to the session as a device input */
    AVCaptureDevice *videoDevice = strm->af->dev_info[strm->param.cap_id].dev;
    strm->dev_input = [AVCaptureDeviceInput deviceInputWithDevice:videoDevice error: &error];
    if (!strm->dev_input) {
        status = PJMEDIA_EVID_SYSERR;
        return;
    }

    [strm->cap_session addInput:strm->dev_input];

    strm->video_output = [[AVCaptureVideoDataOutput alloc] init];
    if (!strm->video_output) {
        status = PJMEDIA_EVID_SYSERR;
        return;
    }
    [strm->cap_session addOutput:strm->video_output];

    /* Configure the video output */
    strm->video_output.alwaysDiscardsLateVideoFrames = YES;
    /* The Apple provided documentation says the only supported key is kCVPixelBufferPixelFormatTypeKey,
     * but it turns out kCVPixelBufferWidthKey and kCVPixelBufferHeightKey are also required. Thanks
     * Chromium, for figuring it out.*/
    strm->video_output.videoSettings =
        [NSDictionary dictionaryWithObjectsAndKeys: @(fi->avf_format),
                                                    kCVPixelBufferPixelFormatTypeKey,
                                                    @(vfd->size.w),
                                                    kCVPixelBufferWidthKey,
                                                    @(vfd->size.h),
                                                    kCVPixelBufferHeightKey,
                                                    nil];
    strm->delegate = [[AVFDelegate alloc] init];
    strm->delegate->stream = strm;
    dispatch_queue_t queue = dispatch_queue_create("AVFQueue", NULL);
    [strm->video_output setSampleBufferDelegate:strm->delegate queue:queue];
    dispatch_release(queue);
}

static void run_func_on_video_queue(struct avf_stream *strm, func_ptr func)
{
    dispatch_sync(strm->video_ops_queue, ^{
        (*func)(strm);
    });
}

/* API: create stream */
static pj_status_t avf_factory_create_stream(pjmedia_vid_dev_factory *f,
					     pjmedia_vid_dev_param *param,
					     const pjmedia_vid_dev_cb *cb,
					     void *user_data,
					     pjmedia_vid_dev_stream **p_vid_strm)
{
    struct avf_factory *af = (struct avf_factory*)f;
    pj_pool_t *pool;
    struct avf_stream *strm;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_format_detail *vfd;
    pj_status_t status = PJ_SUCCESS;

    PJ_ASSERT_RETURN(f && param && p_vid_strm, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->fmt.type == PJMEDIA_TYPE_VIDEO &&
		     param->fmt.detail_type == PJMEDIA_FORMAT_DETAIL_VIDEO &&
                     param->dir == PJMEDIA_DIR_CAPTURE,
		     PJ_EINVAL);

    vfi = pjmedia_get_video_format_info(NULL, param->fmt.id);
    if (!vfi)
        return PJMEDIA_EVID_BADFORMAT;

    /* Create and Initialize stream descriptor */
    pool = pj_pool_create(af->pf, "avf-dev", 4000, 4000, NULL);
    PJ_ASSERT_RETURN(pool != NULL, PJ_ENOMEM);

    strm = PJ_POOL_ZALLOC_T(pool, struct avf_stream);
    pj_memcpy(&strm->param, param, sizeof(*param));
    strm->pool = pool;
    pj_memcpy(&strm->vid_cb, cb, sizeof(*cb));
    strm->user_data = user_data;
    strm->af = af;

    vfd = pjmedia_format_get_video_format_detail(&strm->param.fmt, PJ_TRUE);
    pj_memcpy(&strm->size, &vfd->size, sizeof(vfd->size));
    pj_assert(vfd->fps.num);
    strm->cap_ts_inc = PJMEDIA_SPF2(strm->param.clock_rate, &vfd->fps, 1);

    /* Create dispatch queue */
    strm->video_ops_queue = dispatch_queue_create("AVF Video Ops", DISPATCH_QUEUE_SERIAL);

    /* Create capture stream here */
    strm->status = PJ_SUCCESS;
    run_func_on_video_queue(strm, init_avf_stream);
    status = strm->status;
    if (status != PJ_SUCCESS) {
        dispatch_release(strm->video_ops_queue);
        avf_stream_destroy((pjmedia_vid_dev_stream *)strm);
        return status;
    }

    /* Update param as output */
    param->fmt = strm->param.fmt;

    /* Done */
    strm->base.op = &stream_op;
    *p_vid_strm = &strm->base;

    return PJ_SUCCESS;
}

/* API: Get stream info. */
static pj_status_t avf_stream_get_param(pjmedia_vid_dev_stream *s,
				        pjmedia_vid_dev_param *pi)
{
    struct avf_stream *strm = (struct avf_stream*)s;
    PJ_ASSERT_RETURN(strm && pi, PJ_EINVAL);

    pj_memcpy(pi, &strm->param, sizeof(*pi));

    return PJ_SUCCESS;
}

/* API: get capability */
static pj_status_t avf_stream_get_cap(pjmedia_vid_dev_stream *s,
				      pjmedia_vid_dev_cap cap,
				      void *pval)
{
    struct avf_stream *strm = (struct avf_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_UNUSED_ARG(cap);
    PJ_UNUSED_ARG(pval);

    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    return PJMEDIA_EVID_INVCAP;
}

/* API: set capability */
static pj_status_t avf_stream_set_cap(pjmedia_vid_dev_stream *s,
				     pjmedia_vid_dev_cap cap,
				     const void *pval)
{
    struct avf_stream *strm = (struct avf_stream*)s;

    PJ_UNUSED_ARG(strm);
    PJ_UNUSED_ARG(cap);
    PJ_UNUSED_ARG(pval);

    PJ_ASSERT_RETURN(s && pval, PJ_EINVAL);

    return PJMEDIA_EVID_INVCAP;
}

static void start_avf(struct avf_stream *strm)
{
    [strm->cap_session startRunning];
}

static void stop_avf(struct avf_stream *strm)
{
    [strm->cap_session stopRunning];
}

/* API: Start stream. */
static pj_status_t avf_stream_start(pjmedia_vid_dev_stream *strm)
{
    struct avf_stream *stream = (struct avf_stream*)strm;

    PJ_LOG(4, (THIS_FILE, "Starting avf video stream"));

    if (stream->cap_session) {
        run_func_on_video_queue(stream, start_avf);
	if (![stream->cap_session isRunning])
	    return PJMEDIA_EVID_NOTREADY;
        stream->is_running = PJ_TRUE;
    }

    return PJ_SUCCESS;
}

/* API: Stop stream. */
static pj_status_t avf_stream_stop(pjmedia_vid_dev_stream *strm)
{
    struct avf_stream *stream = (struct avf_stream*)strm;

    PJ_LOG(4, (THIS_FILE, "Stopping avf video stream"));

    if (stream->cap_session && [stream->cap_session isRunning]) {
        int i;
        stream->cap_exited = PJ_FALSE;
        run_func_on_video_queue(stream, stop_avf);
        stream->is_running = PJ_FALSE;
        for (i = 50; i >= 0 && !stream->cap_exited; i--) {
            pj_thread_sleep(10);
        }
    }

    return PJ_SUCCESS;
}

static void destroy_avf(struct avf_stream *strm)
{
    if (strm->cap_session) {
        [strm->cap_session removeInput:strm->dev_input];
        [strm->cap_session removeOutput:strm->video_output];
	[strm->cap_session release];
	strm->cap_session = NULL;
    }

    if (strm->delegate) {
	[strm->delegate release];
	strm->delegate = NULL;
    }

    if (strm->dev_input) {
	strm->dev_input = NULL;
    }
    if (strm->video_output) {
	strm->video_output = NULL;
    }
}

/* API: Destroy stream. */
static pj_status_t avf_stream_destroy(pjmedia_vid_dev_stream *strm)
{
    struct avf_stream *stream = (struct avf_stream*)strm;

    PJ_ASSERT_RETURN(stream != NULL, PJ_EINVAL);

    avf_stream_stop(strm);
    run_func_on_video_queue(stream, destroy_avf);

    dispatch_release(stream->video_ops_queue);
    pj_pool_release(stream->pool);

    return PJ_SUCCESS;
}

#endif	/* PJMEDIA_VIDEO_DEV_HAS_AVF */

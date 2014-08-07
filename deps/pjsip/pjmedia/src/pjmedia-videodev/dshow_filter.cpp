/* $Id: dshowclasses.cpp 4062 2012-04-19 06:36:57Z ming $ */
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

#include <pjmedia-videodev/config.h>


#if defined(PJMEDIA_VIDEO_DEV_HAS_DSHOW) && PJMEDIA_VIDEO_DEV_HAS_DSHOW != 0

#include <DShow.h>
#include <assert.h>
#include <streams.h>

typedef void (*input_callback)(void *user_data, IMediaSample *pMediaSample);

const GUID CLSID_NullRenderer = {0xF9168C5E, 0xCEB2, 0x4FAA, {0xB6, 0xBF,
                                 0x32, 0x9B, 0xF3, 0x9F, 0xA1, 0xE4}};

class NullRenderer: public CBaseRenderer
{
public:
    NullRenderer(HRESULT *pHr);
    virtual ~NullRenderer();

    virtual HRESULT CheckMediaType(const CMediaType *pmt);
    virtual HRESULT DoRenderSample(IMediaSample *pMediaSample);

    input_callback  input_cb;
    void           *user_data;
};

NullRenderer::NullRenderer(HRESULT *pHr): CBaseRenderer(CLSID_NullRenderer,
                                                        "NullRenderer",
                                                        NULL, pHr)
{
    input_cb = NULL;
}

NullRenderer::~NullRenderer()
{
}

HRESULT NullRenderer::CheckMediaType(const CMediaType *pmt)
{
    return S_OK;
}

HRESULT NullRenderer::DoRenderSample(IMediaSample *pMediaSample)
{
    if (input_cb)
        input_cb(user_data, pMediaSample);

    return S_OK;
}

extern "C" IBaseFilter* NullRenderer_Create(input_callback input_cb,
                                             void *user_data)
{
    HRESULT hr;
    NullRenderer *renderer = new NullRenderer(&hr);
    renderer->AddRef();
    renderer->input_cb = input_cb;
    renderer->user_data = user_data;

    return (CBaseFilter *)renderer;
}

#endif	/* PJMEDIA_VIDEO_DEV_HAS_DSHOW */

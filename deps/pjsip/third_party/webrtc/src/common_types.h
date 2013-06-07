/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#ifndef WEBRTC_COMMON_TYPES_H
#define WEBRTC_COMMON_TYPES_H

#include "typedefs.h"

#ifdef WEBRTC_EXPORT
    #define WEBRTC_DLLEXPORT _declspec(dllexport)
#elif WEBRTC_DLL
    #define WEBRTC_DLLEXPORT _declspec(dllimport)
#else
    #define WEBRTC_DLLEXPORT
#endif

#ifndef NULL
    #define NULL 0
#endif

namespace webrtc {

class InStream
{
public:
    virtual int Read(void *buf,int len) = 0;
    virtual int Rewind() {return -1;}
    virtual ~InStream() {}
protected:
    InStream() {}
};

class OutStream
{
public:
    virtual bool Write(const void *buf,int len) = 0;
    virtual int Rewind() {return -1;}
    virtual ~OutStream() {}
protected:
    OutStream() {}
};

enum TraceModule
{
    // not a module, triggered from the engine code
    kTraceVoice              = 0x0001,
    // not a module, triggered from the engine code
    kTraceVideo              = 0x0002,
    // not a module, triggered from the utility code
    kTraceUtility            = 0x0003,
    kTraceRtpRtcp            = 0x0004,
    kTraceTransport          = 0x0005,
    kTraceSrtp               = 0x0006,
    kTraceAudioCoding        = 0x0007,
    kTraceAudioMixerServer   = 0x0008,
    kTraceAudioMixerClient   = 0x0009,
    kTraceFile               = 0x000a,
    kTraceAudioProcessing    = 0x000b,
    kTraceVideoCoding        = 0x0010,
    kTraceVideoMixer         = 0x0011,
    kTraceAudioDevice        = 0x0012,
    kTraceVideoRenderer      = 0x0014,
    kTraceVideoCapture       = 0x0015,
    kTraceVideoPreocessing   = 0x0016
};

enum TraceLevel
{
    kTraceNone               = 0x0000,    // no trace
    kTraceStateInfo          = 0x0001,
    kTraceWarning            = 0x0002,
    kTraceError              = 0x0004,
    kTraceCritical           = 0x0008,
    kTraceApiCall            = 0x0010,
    kTraceDefault            = 0x00ff,

    kTraceModuleCall         = 0x0020,
    kTraceMemory             = 0x0100,   // memory info
    kTraceTimer              = 0x0200,   // timing info
    kTraceStream             = 0x0400,   // "continuous" stream of data

    // used for debug purposes
    kTraceDebug              = 0x0800,  // debug
    kTraceInfo               = 0x1000,  // debug info

    kTraceAll                = 0xffff
};

// External Trace API
class TraceCallback
{
public:
    virtual void Print(const TraceLevel level,
                       const char *traceString,
                       const int length) = 0;
protected:
    virtual ~TraceCallback() {}
    TraceCallback() {}
};


enum FileFormats
{
    kFileFormatWavFile        = 1,
    kFileFormatCompressedFile = 2,
    kFileFormatAviFile        = 3,
    kFileFormatPreencodedFile = 4,
    kFileFormatPcm16kHzFile   = 7,
    kFileFormatPcm8kHzFile    = 8,
    kFileFormatPcm32kHzFile   = 9
};


enum ProcessingTypes
{
    kPlaybackPerChannel = 0,
    kPlaybackAllChannelsMixed,
    kRecordingPerChannel,
    kRecordingAllChannelsMixed
};

// Encryption enums
enum CipherTypes
{
    kCipherNull               = 0,
    kCipherAes128CounterMode  = 1
};

enum AuthenticationTypes
{
    kAuthNull       = 0,
    kAuthHmacSha1   = 3
};

enum SecurityLevels
{
    kNoProtection                    = 0,
    kEncryption                      = 1,
    kAuthentication                  = 2,
    kEncryptionAndAuthentication     = 3
};

class Encryption
{
public:
    virtual void encrypt(
        int channel_no,
        unsigned char* in_data,
        unsigned char* out_data,
        int bytes_in,
        int* bytes_out) = 0;

    virtual void decrypt(
        int channel_no,
        unsigned char* in_data,
        unsigned char* out_data,
        int bytes_in,
        int* bytes_out) = 0;

    virtual void encrypt_rtcp(
        int channel_no,
        unsigned char* in_data,
        unsigned char* out_data,
        int bytes_in,
        int* bytes_out) = 0;

    virtual void decrypt_rtcp(
        int channel_no,
        unsigned char* in_data,
        unsigned char* out_data,
        int bytes_in,
        int* bytes_out) = 0;

protected:
    virtual ~Encryption() {}
    Encryption() {}
};

// External transport callback interface
class Transport
{
public:
    virtual int SendPacket(int channel, const void *data, int len) = 0;
    virtual int SendRTCPPacket(int channel, const void *data, int len) = 0;

protected:
    virtual ~Transport() {}
    Transport() {}
};

// ==================================================================
// Voice specific types
// ==================================================================

// Each codec supported can be described by this structure.
struct CodecInst
{
    int pltype;
    char plname[32];
    int plfreq;
    int pacsize;
    int channels;
    int rate;
};

enum FrameType
{
    kFrameEmpty            = 0,
    kAudioFrameSpeech      = 1,
    kAudioFrameCN          = 2,
    kVideoFrameKey         = 3,    // independent frame
    kVideoFrameDelta       = 4,    // depends on the previus frame
    kVideoFrameGolden      = 5,    // depends on a old known previus frame
    kVideoFrameAltRef      = 6
};

// RTP
enum {kRtpCsrcSize = 15}; // RFC 3550 page 13

enum RTPDirections
{
    kRtpIncoming = 0,
    kRtpOutgoing
};

enum PayloadFrequencies
{
    kFreq8000Hz = 8000,
    kFreq16000Hz = 16000,
    kFreq32000Hz = 32000
};

enum VadModes                 // degree of bandwidth reduction
{
    kVadConventional = 0,      // lowest reduction
    kVadAggressiveLow,
    kVadAggressiveMid,
    kVadAggressiveHigh         // highest reduction
};

struct NetworkStatistics           // NETEQ statistics
{
    // current jitter buffer size in ms
    WebRtc_UWord16 currentBufferSize;
    // preferred (optimal) buffer size in ms
    WebRtc_UWord16 preferredBufferSize;
    // loss rate (network + late) in percent (in Q14)
    WebRtc_UWord16 currentPacketLossRate;
    // late loss rate in percent (in Q14)
    WebRtc_UWord16 currentDiscardRate;
    // fraction (of original stream) of synthesized speech inserted through
    // expansion (in Q14)
    WebRtc_UWord16 currentExpandRate;
    // fraction of synthesized speech inserted through pre-emptive expansion
    // (in Q14)
    WebRtc_UWord16 currentPreemptiveRate;
    // fraction of data removed through acceleration (in Q14)
    WebRtc_UWord16 currentAccelerateRate;
};

struct JitterStatistics
{
    // smallest Jitter Buffer size during call in ms
    WebRtc_UWord32 jbMinSize;
    // largest Jitter Buffer size during call in ms
    WebRtc_UWord32 jbMaxSize;
    // the average JB size, measured over time - ms
    WebRtc_UWord32 jbAvgSize;
    // number of times the Jitter Buffer changed (using Accelerate or
    // Pre-emptive Expand)
    WebRtc_UWord32 jbChangeCount;
    // amount (in ms) of audio data received late
    WebRtc_UWord32 lateLossMs;
    // milliseconds removed to reduce jitter buffer size
    WebRtc_UWord32 accelerateMs;
    // milliseconds discarded through buffer flushing
    WebRtc_UWord32 flushedMs;
    // milliseconds of generated silence
    WebRtc_UWord32 generatedSilentMs;
    // milliseconds of synthetic audio data (non-background noise)
    WebRtc_UWord32 interpolatedVoiceMs;
    // milliseconds of synthetic audio data (background noise level)
    WebRtc_UWord32 interpolatedSilentMs;
    // count of tiny expansions in output audio
    WebRtc_UWord32 countExpandMoreThan120ms;
    // count of small expansions in output audio
    WebRtc_UWord32 countExpandMoreThan250ms;
    // count of medium expansions in output audio
    WebRtc_UWord32 countExpandMoreThan500ms;
    // count of long expansions in output audio
    WebRtc_UWord32 countExpandMoreThan2000ms;
    // duration of longest audio drop-out
    WebRtc_UWord32 longestExpandDurationMs;
    // count of times we got small network outage (inter-arrival time in
    // [500, 1000) ms)
    WebRtc_UWord32 countIAT500ms;
    // count of times we got medium network outage (inter-arrival time in
    // [1000, 2000) ms)
    WebRtc_UWord32 countIAT1000ms;
    // count of times we got large network outage (inter-arrival time >=
    // 2000 ms)
    WebRtc_UWord32 countIAT2000ms;
    // longest packet inter-arrival time in ms
    WebRtc_UWord32 longestIATms;
    // min time incoming Packet "waited" to be played
    WebRtc_UWord32 minPacketDelayMs;
    // max time incoming Packet "waited" to be played
    WebRtc_UWord32 maxPacketDelayMs;
    // avg time incoming Packet "waited" to be played
    WebRtc_UWord32 avgPacketDelayMs;
};

typedef struct
{
    int min;              // minumum
    int max;              // maximum
    int average;          // average
} StatVal;

typedef struct           // All levels are reported in dBm0
{
    StatVal speech_rx;   // long-term speech levels on receiving side
    StatVal speech_tx;   // long-term speech levels on transmitting side
    StatVal noise_rx;    // long-term noise/silence levels on receiving side
    StatVal noise_tx;    // long-term noise/silence levels on transmitting side
} LevelStatistics;

typedef struct        // All levels are reported in dB
{
    StatVal erl;      // Echo Return Loss
    StatVal erle;     // Echo Return Loss Enhancement
    StatVal rerl;     // RERL = ERL + ERLE
    // Echo suppression inside EC at the point just before its NLP
    StatVal a_nlp;
} EchoStatistics;

enum TelephoneEventDetectionMethods
{
    kInBand = 0,
    kOutOfBand = 1,
    kInAndOutOfBand = 2
};

enum NsModes    // type of Noise Suppression
{
    kNsUnchanged = 0,   // previously set mode
    kNsDefault,         // platform default
    kNsConference,      // conferencing default
    kNsLowSuppression,  // lowest suppression
    kNsModerateSuppression,
    kNsHighSuppression,
    kNsVeryHighSuppression,     // highest suppression
};

enum AgcModes                  // type of Automatic Gain Control
{
    kAgcUnchanged = 0,        // previously set mode
    kAgcDefault,              // platform default
    // adaptive mode for use when analog volume control exists (e.g. for
    // PC softphone)
    kAgcAdaptiveAnalog,
    // scaling takes place in the digital domain (e.g. for conference servers
    // and embedded devices)
    kAgcAdaptiveDigital,
    // can be used on embedded devices where the the capture signal is level
    // is predictable
    kAgcFixedDigital
};

// EC modes
enum EcModes                   // type of Echo Control
{
    kEcUnchanged = 0,          // previously set mode
    kEcDefault,                // platform default
    kEcConference,             // conferencing default (aggressive AEC)
    kEcAec,                    // Acoustic Echo Cancellation
    kEcAecm,                   // AEC mobile
};

// AECM modes
enum AecmModes                 // mode of AECM
{
    kAecmQuietEarpieceOrHeadset = 0,
                               // Quiet earpiece or headset use
    kAecmEarpiece,             // most earpiece use
    kAecmLoudEarpiece,         // Loud earpiece or quiet speakerphone use
    kAecmSpeakerphone,         // most speakerphone use (default)
    kAecmLoudSpeakerphone      // Loud speakerphone
};

// AGC configuration
typedef struct
{
    unsigned short targetLeveldBOv;
    unsigned short digitalCompressionGaindB;
    bool           limiterEnable;
} AgcConfig;                  // AGC configuration parameters

enum StereoChannel
{
    kStereoLeft = 0,
    kStereoRight,
    kStereoBoth
};

// Audio device layers
enum AudioLayers
{
    kAudioPlatformDefault = 0,
    kAudioWindowsWave = 1,
    kAudioWindowsCore = 2,
    kAudioLinuxAlsa = 3,
    kAudioLinuxPulse = 4
};

enum NetEqModes             // NetEQ playout configurations
{
    // Optimized trade-off between low delay and jitter robustness for two-way
    // communication.
    kNetEqDefault = 0,
    // Improved jitter robustness at the cost of increased delay. Can be
    // used in one-way communication.
    kNetEqStreaming = 1,
    // Optimzed for decodability of fax signals rather than for perceived audio
    // quality.
    kNetEqFax = 2,
};

enum NetEqBgnModes          // NetEQ Background Noise (BGN) configurations
{
    // BGN is always on and will be generated when the incoming RTP stream
    // stops (default).
    kBgnOn = 0,
    // The BGN is faded to zero (complete silence) after a few seconds.
    kBgnFade = 1,
    // BGN is not used at all. Silence is produced after speech extrapolation
    // has faded.
    kBgnOff = 2,
};

enum OnHoldModes            // On Hold direction
{
    kHoldSendAndPlay = 0,    // Put both sending and playing in on-hold state.
    kHoldSendOnly,           // Put only sending in on-hold state.
    kHoldPlayOnly            // Put only playing in on-hold state.
};

enum AmrMode
{
    kRfc3267BwEfficient = 0,
    kRfc3267OctetAligned = 1,
    kRfc3267FileStorage = 2,
};

// ==================================================================
// Video specific types
// ==================================================================

// Raw video types
enum RawVideoType
{
    kVideoI420     = 0,
    kVideoYV12     = 1,
    kVideoYUY2     = 2,
    kVideoUYVY     = 3,
    kVideoIYUV     = 4,
    kVideoARGB     = 5,
    kVideoRGB24    = 6,
    kVideoRGB565   = 7,
    kVideoARGB4444 = 8,
    kVideoARGB1555 = 9,
    kVideoMJPEG    = 10,
    kVideoNV12     = 11,
    kVideoNV21     = 12,
    kVideoUnknown  = 99
};

// Video codec
enum { kConfigParameterSize = 128};
enum { kPayloadNameSize = 32};

// H.263 specific
struct VideoCodecH263
{
    char quality;
};

// H.264 specific
enum H264Packetization
{
    kH264SingleMode         = 0,
    kH264NonInterleavedMode = 1
};

enum VideoCodecComplexity
{
    kComplexityNormal = 0,
    kComplexityHigh    = 1,
    kComplexityHigher  = 2,
    kComplexityMax     = 3
};

enum VideoCodecProfile
{
    kProfileBase = 0x00,
    kProfileMain = 0x01
};

struct VideoCodecH264
{
    H264Packetization          packetization;
    VideoCodecComplexity       complexity;
    VideoCodecProfile          profile;
    char                       level;
    char                       quality;

    bool                       useFMO;

    unsigned char              configParameters[kConfigParameterSize];
    unsigned char              configParametersSize;
};

// VP8 specific
struct VideoCodecVP8
{
    bool                       pictureLossIndicationOn;
    bool                       feedbackModeOn;
    VideoCodecComplexity       complexity;
};

// MPEG-4 specific
struct VideoCodecMPEG4
{
    unsigned char   configParameters[kConfigParameterSize];
    unsigned char   configParametersSize;
    char            level;
};

// Unknown specific
struct VideoCodecGeneric
{
};

// Video codec types
enum VideoCodecType
{
    kVideoCodecH263,
    kVideoCodecH264,
    kVideoCodecVP8,
    kVideoCodecMPEG4,
    kVideoCodecI420,
    kVideoCodecRED,
    kVideoCodecULPFEC,
    kVideoCodecUnknown
};

union VideoCodecUnion
{
    VideoCodecH263      H263;
    VideoCodecH264      H264;
    VideoCodecVP8       VP8;
    VideoCodecMPEG4     MPEG4;
    VideoCodecGeneric   Generic;
};

// Common video codec properties
struct VideoCodec
{
    VideoCodecType      codecType;
    char                plName[kPayloadNameSize];
    unsigned char       plType;

    unsigned short      width;
    unsigned short      height;

    unsigned int        startBitrate;
    unsigned int        maxBitrate;
    unsigned int        minBitrate;
    unsigned char       maxFramerate;

    VideoCodecUnion     codecSpecific;

    unsigned int        qpMax;
};

}  // namespace webrtc

#endif  // WEBRTC_COMMON_TYPES_H

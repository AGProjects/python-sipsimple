/*
cencoder.c - c source to a base64 encoding algorithm implementation

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

#include <libzrtpcpp/zrtpB64Encode.h>

const int CHARS_PER_LINE = 72;

void base64_init_encodestate(base64_encodestate* state_in, int lineLength)
{
    state_in->step = step_A;
    state_in->result = 0;
    state_in->stepcount = 0;
    if (lineLength < 0)
        state_in->lineLength = CHARS_PER_LINE / 4;
    else
        state_in->lineLength = (lineLength+3) / 4;
}

char base64_encode_value(const int8_t value_in)
{
    static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (value_in > 63) return '=';
    return encoding[(int)value_in];
}

int base64_encode_block(const uint8_t *plaintext_in, int length_in, char* code_out, base64_encodestate* state_in)
{
    const uint8_t *plainchar = plaintext_in;
    const uint8_t *const plaintextend = plaintext_in + length_in;
    char* codechar = code_out;
    char result;
    char fragment;

    result = state_in->result;

    switch (state_in->step)
    {
        while (1)
        {
        case step_A:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_A;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result = (fragment & 0x0fc) >> 2;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x003) << 4;
        case step_B:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_B;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0f0) >> 4;
            *codechar++ = base64_encode_value(result);
            result = (fragment & 0x00f) << 2;
        case step_C:
            if (plainchar == plaintextend)
            {
                state_in->result = result;
                state_in->step = step_C;
                return codechar - code_out;
            }
            fragment = *plainchar++;
            result |= (fragment & 0x0c0) >> 6;
            *codechar++ = base64_encode_value(result);
            result  = (fragment & 0x03f) >> 0;
            *codechar++ = base64_encode_value(result);

            if (state_in->lineLength > 0) {
                state_in->stepcount++;
                if (state_in->stepcount == state_in->lineLength)
                {
                    *codechar++ = '\n';
                    state_in->stepcount = 0;
                }
            }
        }
    }
    /* control should not reach here */
    return codechar - code_out;
}

int base64_encode_blockend(char* code_out, base64_encodestate* state_in)
{
    char* codechar = code_out;

    switch (state_in->step)
    {
        case step_B:
            *codechar++ = base64_encode_value(state_in->result);
            *codechar++ = '=';
            *codechar++ = '=';
            break;
        case step_C:
            *codechar++ = base64_encode_value(state_in->result);
            *codechar++ = '=';
            break;
        case step_A:
            break;
    }
    if (state_in->lineLength > 0)
        *codechar++ = '\n';

    return codechar - code_out;
}


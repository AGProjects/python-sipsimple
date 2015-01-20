/*
  Copyright (C) 2010-2013 Werner Dittmann

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <cryptcommon/macSkein.h>
#include <stdlib.h>

void macSkein(uint8_t* key, int32_t key_length,
               const uint8_t* data, uint32_t data_length,
               uint8_t* mac, int32_t mac_length, SkeinSize_t skeinSize)
{
    SkeinCtx_t ctx;

    skeinCtxPrepare(&ctx, skeinSize);

    skeinMacInit(&ctx, key, key_length, mac_length);
    skeinUpdate(&ctx, data, data_length);
    skeinFinal(&ctx, mac);
}

void macSkein(uint8_t* key, int32_t key_length,
               const uint8_t* data[], uint32_t data_length[],
               uint8_t* mac, int32_t mac_length, SkeinSize_t skeinSize)
{
    SkeinCtx_t ctx;

    skeinCtxPrepare(&ctx, skeinSize);

    skeinMacInit(&ctx, key, key_length, mac_length);
    while (*data) {
        skeinUpdate(&ctx, *data, *data_length);
        data++;
        data_length ++;
    }
    skeinFinal(&ctx, mac);
}

void* createSkeinMacContext(uint8_t* key, int32_t key_length, 
                            int32_t mac_length, SkeinSize_t skeinSize)
{
    SkeinCtx_t* ctx = (SkeinCtx_t*)malloc(sizeof(SkeinCtx_t));
    if (ctx == NULL)
        return NULL;

    skeinCtxPrepare(ctx, skeinSize);
    skeinMacInit(ctx, key, key_length, mac_length);
    return ctx;
}

void* initializeSkeinMacContext(void* ctx, uint8_t* key, int32_t key_length, int32_t mac_length, SkeinSize_t skeinSize)
{
    SkeinCtx_t* pctx = (SkeinCtx_t*)ctx;

    skeinCtxPrepare(pctx, skeinSize);
    skeinMacInit(pctx, key, key_length, mac_length);
    return (void*)pctx;
}

void macSkeinCtx(void* ctx, const uint8_t* data, uint32_t data_length,
                uint8_t* mac)
{
    SkeinCtx_t* pctx = (SkeinCtx_t*)ctx;

    skeinUpdate(pctx, data, data_length);
    skeinFinal(pctx, mac);
    skeinReset(pctx);
}

void macSkeinCtx(void* ctx, const uint8_t* data[], uint32_t data_length[],
                uint8_t* mac)
{
    SkeinCtx_t* pctx = (SkeinCtx_t*)ctx;

    while (*data) {
        skeinUpdate(pctx, *data, *data_length);
        data++;
        data_length++;
    }
    skeinFinal(pctx, mac);
    skeinReset(pctx);
}

void freeSkeinMacContext(void* ctx)
{
    if (ctx)
        free(ctx);
}

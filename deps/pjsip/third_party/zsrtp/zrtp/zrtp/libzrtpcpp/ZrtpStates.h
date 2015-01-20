/*
  Copyright (C) 2006-2013 Werner Dittmann

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

/*
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#ifndef _ZRTPSTATES_H_
#define _ZRTPSTATES_H_

/**
 * @file ZrtpStates.h
 * @brief The ZRTP state switching class
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

class __EXPORT ZrtpStateClass;
/**
 * This structure hold the state name as enum (int) number and the pointer to
 * the functions that handles the various triggers that can occur in a state.
 */
typedef struct  {
    int32_t stateName;                      ///< The state number
    void (ZrtpStateClass::* handler)(void); ///< The state handler
} state_t;

/**
 * Implement a simple state switching.
 *
 * This class provides functions that manage the states and the event handler
 * functions. Its a very simple implementation.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

class __EXPORT ZrtpStates {
 public:

    /// Create an initialize state switching
    ZrtpStates(state_t* const zstates,
           const int32_t numStates,
           const int32_t initialState):
    numStates(numStates), states(zstates), state(initialState) {}

    /// Call a state handler
    int32_t processEvent(ZrtpStateClass& zsc) {
        (zsc.*states[state].handler)();
        return 0;
    }

    /// Check if in specified state
    bool inState(const int32_t s) { return ((s == state)); }

    /// Set the next state
    void nextState(int32_t s)        { state = s; }

 private:
    const int32_t numStates;
    const state_t* states;
    int32_t  state;

    ZrtpStates();
};

/**
 * @}
 */
#endif  //ZRTPSTATES


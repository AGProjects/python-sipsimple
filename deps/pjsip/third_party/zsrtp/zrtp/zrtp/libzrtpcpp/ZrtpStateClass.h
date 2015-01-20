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

#ifndef _ZRTPSTATECLASS_H_
#define _ZRTPSTATECLASS_H_

/**
 * @file ZrtpStateClass.h
 * @brief The ZRTP state handling class
 *
 * @ingroup GNU_ZRTP
 * @{
 */

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStates.h>
#include <libzrtpcpp/ZrtpPacketBase.h>

/**
 * The ZRTP states
 *
 * Depending on the role of this state engine and the actual protocl flow
 * not all states are processed during a ZRTP handshake.
 */
enum zrtpStates {
    Initial,            ///< Initial state after starting the state engine
    Detect,             ///< State sending Hello, try to detect answer message
    AckDetected,        ///< HelloAck received
    AckSent,            ///< HelloAck sent after Hello received
    WaitCommit,         ///< Wait for a Commit message
    CommitSent,         ///< Commit message sent
    WaitDHPart2,        ///< Wait for a DHPart2 message
    WaitConfirm1,       ///< Wait for a Confirm1 message
    WaitConfirm2,       ///< Wait for a confirm2 message
    WaitConfAck,        ///< Wait for Conf2Ack
    WaitClearAck,       ///< Wait for clearAck - not used
    SecureState,        ///< This is the secure state - SRTP active
    WaitErrorAck,       ///< Wait for ErrorAck message
    numberOfStates      ///< Gives total number of protocol states
};

enum EventReturnCodes {
    Fail = 0,           ///< ZRTP event processing failed.
    Done = 1            ///< Event processing ok.
};

enum EventDataType {
    ZrtpInitial = 1,    ///< Initial event, enter Initial state
    ZrtpClose,          ///< Close event, shut down state engine
    ZrtpPacket,         ///< Normal ZRTP message event, process according to state
    Timer,              ///< Timer event
    ErrorPkt            ///< Error packet event
};

enum SecureSubStates {
    Normal,
    WaitSasRelayAck,
    numberofSecureSubStates
};

/// A ZRTP state event
typedef struct Event {
    EventDataType type; ///< Type of event
    size_t   length;    ///< length of the message data
    uint8_t* packet;    ///< Event data if availabe, usually a ZRTP message
} Event_t;


/**
 * The ZRTP timer structure.
 *
 * This structure holds all necessary data to compute the timer for
 * the protocol timers. The state engine allocate one structure for
 * each timer. ZRTP uses two timers, T1 and T2, to monitor protocol
 * timeouts. As a slight misuse but to make overall handling a bit
 * simpler this structure also contains the resend counter. This is
 * possible in ZRTP because it uses a simple timeout strategy.
 */
typedef struct zrtpTimer {
    int32_t time,       ///< Current timeout value
    start,              ///< Start value for timeout
    increment,          ///< increment timeout after each timeout event (not used anymore)
    capping,            ///< Maximum timeout value
    counter,            ///< Current number of timeouts
    maxResend;          ///< Maximum number of timeout resends
} zrtpTimer_t;


class ZRtp;

/**
 * This class is the ZRTP protocol state engine.
 *
 * This class is responsible to handle the ZRTP protocol. It does not
 * handle the ZRTP HMAC, DH, and other data management. This is done in
 * class ZRtp, which is the parent of this class.
 *
 * The methods of this class implement the ZRTP state actions.
 *
 */


class __EXPORT ZrtpStateClass {

private:
    ZRtp* parent;           ///< The ZRTP implmentation
    ZrtpStates* engine;     ///< The state switching engine
    Event_t* event;         ///< Current event to process

    /**
     * The last packet that was sent.
     *
     * If we are <code>Initiator</code> then resend this packet in case of
     * timeout.
     */
    ZrtpPacketBase* sentPacket;

    /**
     * Points to prepared Commit packet after receiving a Hello packet
     */
    ZrtpPacketCommit* commitPkt;

    zrtpTimer_t T1;         ///< The Hello message timeout timer
    zrtpTimer_t T2;         ///< Timeout timer for other messages

    int32_t t1Resend;       ///< configurable resend counter for T1 (Hello packets)
    int32_t t1ResendExtend; ///< configurable extended resend counter for T1 (Hello packets)
    int32_t t2Resend;       ///< configurable resend counter for T2 (other packets)

    /*
     * If this is set to true the protocol engine handle the multi-stream
     * variant of ZRTP. Refer to chapter 5.4.2 in the ZRTP specification.
     */
    bool multiStream;

    // Secure substate to handle SAS relay packets
    SecureSubStates secSubstate;

    /**
     * Secure Sub state WaitSasRelayAck.
     *
     * This state belongs to the secure substates and handles
     * SAS Relay Ack. 
     *
     * When entering this transition function
     * - sentPacket contains Error packet, Error timer active
     *
     * Possible events in this state are:
     * - timeout for sent SAS Relay packet: causes a resend check and repeat sending
     *   of packet
     * - SASRelayAck: Stop timer and switch to secure substate Normal.
     */
    bool subEvWaitRelayAck();

    /**
     * Hello packet version sent to other partner
     */
    int32_t sentVersion;
    
    int32_t retryCounters[ErrorRetry+1];  // TODO adjust

public:
    /// Create a ZrtpStateClass
    ZrtpStateClass(ZRtp *p);
    ~ZrtpStateClass();

    /// Check if in a specified state
    bool inState(const int32_t state) { return engine->inState(state); };

    /// Switch to the specified state
    void nextState(int32_t state)        { engine->nextState(state); };

    /// Process an event, the main entry point into the state engine
    void processEvent(Event_t *ev);

    /**
     * The state event handling methods.
     *
     * Refer to the protocol state diagram for further documentation.
     */
    /// Initial event state
    void evInitial();

    /// Detect state
    void evDetect();

    /// HelloAck detected state
    void evAckDetected();

    /// HelloAck sent state
    void evAckSent();

    /// Wait for Commit message
    void evWaitCommit();

    /// Commit sent state
    void evCommitSent();

    /// Wait for DHPart2 message
    void evWaitDHPart2();

    /// Wait for Confirm2 message
    void evWaitConfirm1();

    /// Wait for Confirm2 message
    void evWaitConfirm2();

    /// Wait for ConfAck message
    void evWaitConfAck();

    /// Wait for ClearAck message (not used)
    void evWaitClearAck();

    /// Secure reached state
    void evSecureState();

    /// Wait for ErrorAck message
    void evWaitErrorAck();

    /**
     * Initialize and activate a timer.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     */
    int32_t startTimer(zrtpTimer_t *t);

    /**
     * Compute and set the next timeout value.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     *   -1 resend counter exceeded
     */
    int32_t nextTimer(zrtpTimer_t *t);

    /**
     * Cancel the active timer.
     *
     * @return
     *    1 timer was canceled
     *    0 cancelation failed
     */
    int32_t cancelTimer() {return parent->cancelTimer(); };

    /**
     * Prepare and send an Error packet.
     *
     * Preparse an Error packet and sends it. It stores the Error
     * packet in the sentPacket variable to enable resending. The
     * method switches to protocol state Initial.
     */
    void sendErrorPacket(uint32_t errorCode);

    /**
     * Set status if an error occured while sending a ZRTP packet.
     *
     * This functions clears data and set the state to Initial after the engine
     * detected a problem while sending a ZRTP packet.
     *
     * @return
     *    Fail code
     */
    void sendFailed();

    /**
     * Set status if a timer problems occure.
     *
     * This functions clears data and set state to Initial after a timer
     * error occured. Either no timer available or resend counter exceedeed.
     *
     * @return
     *    Fail code
     */
    void timerFailed(int32_t subCode);

    /**
     * Set multi-stream mode flag.
     *
     * This functions set the multi-stream mode. The protocol
     * engine will run the multi-stream mode variant of the ZRTP
     * protocol if this flag is set to true.
     *
     * @param multi
     *    Set the multi-stream mode flag to true or false.
     */
    void setMultiStream(bool multi);

    /**
     * Status of multi-stream mode flag.
     *
     * This functions returns the value of the multi-stream mode flag.
     *
     * @return
     *    Value of the multi-stream mode flag.
     */
    bool isMultiStream();

    /**
     * Send a SAS relay packet.
     *
     * the functions stores sends the SAS relay packet and stores the pointer in
     * the sentPacket variable to enable resending.
     *
     * The method switches to secure substate WaitSasRelayAck.
     * 
     * @param relay
     *    Pointer to the SAS relay packet.
     */
    void sendSASRelay(ZrtpPacketSASrelay* relay);

    /**
     * Set the resend counter of timer T1 - T1 controls the Hello packets.
     */
    void setT1Resend(int32_t counter) {T1.maxResend = counter;}

    /**
     * Set the time capping of timer T1 - T1 controls the Hello packets.
     */
    void setT1Capping(int32_t capping) {T1.capping = capping;}

    /**
     * Set the extended resend counter of timer T1 - T1 controls the Hello packets.
     *
     * More retries to extend time, see chap. 6
     */
    void setT1ResendExtend(int32_t counter) {t1ResendExtend = counter;}

    /**
     * Set the resend counter of timer T2 - T2 controls other (post-Hello) packets.
     */
    void setT2Resend(int32_t counter) {T2.maxResend = counter;}

    /**
     * Set the time capping of timer T2 - T2 controls other (post-Hello) packets.
     */
    void setT2Capping(int32_t capping) {T2.capping = capping;}

    /**
     * @brief Get required buffer size to get all 32-bit retry counters
     *
     * @param streamNm stream, if not specified the default is @c AudioStream
     * 
     * @return number of 32 bit integer elements required or < 0 on error
     */
    int getNumberOfRetryCounters();

    /**
     * @brief Read retry counters
     * 
     * @param buffer Pointer to buffer of 32-bit integers. The buffer must be able to
     *         hold at least getNumberOfRetryCounters() 32-bit integers
     * @param streamNm stream, if not specified the default is @c AudioStream
     * 
     * @return number of 32-bit counters returned in buffer or < 0 on error
     */
    int getRetryCounters(int32_t* counters);

};

/**
 * @}
 */
#endif // _ZRTPSTATECLASS_H_


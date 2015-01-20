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

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */

#include <iostream>
#include <cstdlib>
#include <ctype.h>

#include <libzrtpcpp/ZRtp.h>
#include <libzrtpcpp/ZrtpStateClass.h>

using namespace std;
using namespace GnuZrtpCodes;

state_t states[numberOfStates] = {
    {Initial,      &ZrtpStateClass::evInitial },
    {Detect,       &ZrtpStateClass::evDetect },
    {AckDetected,  &ZrtpStateClass::evAckDetected },
    {AckSent,      &ZrtpStateClass::evAckSent },
    {WaitCommit,   &ZrtpStateClass::evWaitCommit },
    {CommitSent,   &ZrtpStateClass::evCommitSent },
    {WaitDHPart2,  &ZrtpStateClass::evWaitDHPart2 },
    {WaitConfirm1, &ZrtpStateClass::evWaitConfirm1 },
    {WaitConfirm2, &ZrtpStateClass::evWaitConfirm2 },
    {WaitConfAck,  &ZrtpStateClass::evWaitConfAck },
    {WaitClearAck, &ZrtpStateClass::evWaitClearAck },
    {SecureState,  &ZrtpStateClass::evSecureState },
    {WaitErrorAck, &ZrtpStateClass::evWaitErrorAck }
};


ZrtpStateClass::ZrtpStateClass(ZRtp *p) : parent(p), commitPkt(NULL), t1Resend(20), t1ResendExtend(60), t2Resend(10),
                                          multiStream(false), secSubstate(Normal), sentVersion(0) {

    engine = new ZrtpStates(states, numberOfStates, Initial);
    memset(retryCounters, 0, sizeof(retryCounters));

    // Set up timers according to ZRTP spec
    T1.start = 50;
    T1.maxResend = t1Resend;
    T1.capping = 800;

    T2.start = 150;
    T2.maxResend = t2Resend;
    T2.capping = 1200;
}

ZrtpStateClass::~ZrtpStateClass(void) {

    // If not in Initial state: close the protocol engine
    // before destroying it. This will free pending packets
    // if necessary.
    if (!inState(Initial)) {
        Event_t ev;

        cancelTimer();
        ev.type = ZrtpClose;
        event = &ev;
        engine->processEvent(*this);
    }
    delete engine;
}

void ZrtpStateClass::processEvent(Event_t *ev) {

    char *msg, first, middle, last;
    uint8_t *pkt;

    parent->synchEnter();

    event = ev;
    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;
        first = tolower(*msg);
        middle = tolower(*(msg+4));
        last = tolower(*(msg+7));

        // Sanity check of packet size for all states except WaitErrorAck.
        if (!inState(WaitErrorAck)) {
            uint16_t totalLength = *(uint16_t*)(pkt+2);
            totalLength = zrtpNtohs(totalLength) * ZRTP_WORD_SIZE;
            totalLength += 12 + sizeof(uint32_t);           // 12 bytes is fixed header, uint32_t is CRC

            if (totalLength != ev->length) {
                fprintf(stderr, "Total length does not match received length: %d - %ld\n", totalLength, (long int)(ev->length & 0xffff));
                sendErrorPacket(MalformedPacket);
                parent->synchLeave();
                return;
            }
        }

        // Check if this is an Error packet.
        if (first == 'e' && middle =='r' && last == ' ') {
            /*
             * Process a received Error packet.
             *
             * In any case stop timer to prevent resending packets.
             * Use callback method to prepare and get an ErrorAck packet.
             * Modify event type to "ErrorPkt" and hand it over to current
             * state for further processing.
             */
            cancelTimer();
            ZrtpPacketError epkt(pkt);
            ZrtpPacketErrorAck* eapkt = parent->prepareErrorAck(&epkt);
            parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(eapkt));
            event->type = ErrorPkt;
        }
        else if (first == 'p' && middle == ' ' && last == ' ') {
            ZrtpPacketPing ppkt(pkt);
            ZrtpPacketPingAck* ppktAck = parent->preparePingAck(&ppkt);
            if (ppktAck != NULL) {          // ACK only to valid PING packet, otherwise ignore it
                parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(ppktAck));
            }
            parent->synchLeave();
            return;
        }
        else if (first == 's' && last == 'y') {
            uint32_t errorCode = 0;
            ZrtpPacketSASrelay* srly = new ZrtpPacketSASrelay(pkt);
            ZrtpPacketRelayAck* rapkt = parent->prepareRelayAck(srly, &errorCode);
            parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(rapkt));
            parent->synchLeave();
            return;
        }
    }
    /*
     * Shut down protocol state engine: cancel outstanding timer, further
     * processing in current state.
     */
    else if (event->type == ZrtpClose) {
        cancelTimer();
    }
    engine->processEvent(*this);
    parent->synchLeave();
}


void ZrtpStateClass::evInitial(void) {
    DEBUGOUT((cout << "Checking for match in Initial.\n"));

    if (event->type == ZrtpInitial) {
        ZrtpPacketHello* hello = parent->prepareHello();
        sentVersion = hello->getVersionInt();

        // remember packet for easy resend in case timer triggers
        sentPacket = static_cast<ZrtpPacketBase *>(hello);

        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        if (startTimer(&T1) <= 0) {
            timerFailed(SevereNoTimer);      // returns to state Initial
            return;
        }
        nextState(Detect);
    }
}

/*
 * Detect state.
 *
 * When in this state the protocol engine sent an initial Hello packet
 * to the peer.
 *
 * When entering this state transition function then:
 * - Assume Initiator mode, mode may change later on peer reaction
 * - Instance variable sentPacket contains the sent Hello packet
 * - Hello timer T1 may be active. This is the case if the other peer
 *   has prepared its RTP session and answers our Hello packets nearly 
 *   immediately, i.e. before the Hello timeout counter expires. If the
 *   other peer does not send a Hello during this time the state engine
 *   reports "other peer does not support ZRTP" but stays
 *   in state Detect with no active timer (passiv mode). Staying in state 
 *   Detect allows another peer to start its detect phase any time later.
 *
 *   This restart capability is the reason why we use "startTimer(&T1)" in 
 *   case we received a Hello packet from another peer. This effectively 
 *   restarts the Hello timeout counter.
 *
 *   In this state we also handle ZrtpInitialize event. This forces a
 *   restart of ZRTP discovery if an application calls ZrtpQueue#startZrtp
 *   again. This may happen after a previous discovery phase were not 
 *   successful.
 *
 *   Usually applications use some sort of signaling protocol, for example
 *   SIP, to negotiate the RTP parameters. Thus the RTP sessions setup is
 *   fairly sychronized and thus also the ZRTP detection phase. Applications
 *   that use some other ways to setup the RTP sessions this restart capability
 *   comes in handy because no RTP setup sychronization is necessary.
 * 
 * Possible events in this state are:
 * - timeout for sent Hello packet: causes a resend check and 
 *   repeat sending of Hello packet
 * - received a HelloAck: stop active timer, prepare and send Hello packet,
 *   switch to state AckDeteced.
 * - received a Hello: stop active timer, send HelloAck, prepare Commit 
 *   packet, switch to state AckSent.
 *
 */
void ZrtpStateClass::evDetect(void) {

    DEBUGOUT((cout << "Checking for match in Detect.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    /*
     * First check the general event type, then discrimnate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));
        /*
         * HelloAck:
         * - our peer acknowledged our Hello packet, we have not seen the peer's Hello yet
         * - cancel timer T1 to stop resending Hello
         * - switch to state AckDetected, wait for peer's Hello (F3)
         * 
         * When we receive an HelloAck this also means that our partner accepted our protocol version.
         */
        if (first == 'h' && last =='k') {
            cancelTimer();
            sentPacket = NULL;
            nextState(AckDetected);
            return;
        }
        /*
         * Hello:
         * - send HelloAck packet to acknowledge the received Hello packet if versions match.
         *   Otherweise negotiate ZRTP versions.
         * - use received Hello packet to prepare own Commit packet. We need to
         *   do it at this point because we need the hash value computed from
         *   peer's Hello packet. Follwing states my use the prepared Commit.
         * - switch to new state AckSent which sends own Hello packet until 
         *   peer acknowledges this
         * - Don't clear sentPacket, points to Hello
         */
        if (first == 'h' && last ==' ') {
            ZrtpPacketHello hpkt(pkt);

            cancelTimer();

            /*
             * Check and negotiate the ZRTP protocol version first.
             *
             * This selection mechanism relies on the fact that we sent the highest supported protocol version in
             * the initial Hello packet with as stated in RFC6189, section 4.1.1
             */
            int32_t recvVersion = hpkt.getVersionInt();
            if (recvVersion > sentVersion) {   // We don't support this version, stay in state with timer active
                if (startTimer(&T1) <= 0) {
                    timerFailed(SevereNoTimer);      // returns to state Initial
                }
                return;
            }

            /*
             * The versions don't match. Start negotiating versions. This negotiation stays in the Detect state.
             * Only if the received version matches our own sent version we start to send a HelloAck.
             */
            if (recvVersion != sentVersion) {
                ZRtp::HelloPacketVersion* hpv = parent->helloPackets;

                int32_t index;
                for (index = 0; hpv->packet && hpv->packet != parent->currentHelloPacket; hpv++, index++)   // Find current sent Hello
                    ;

                for(; index >= 0 && hpv->version > recvVersion; hpv--, index--)   // find a supported version less-equal to received version
                    ;

                if (index < 0) {
                    sendErrorPacket(UnsuppZRTPVersion);
                    return;
                }
                parent->currentHelloPacket = hpv->packet;
                sentVersion = parent->currentHelloPacket->getVersionInt();

                // remember packet for easy resend in case timer triggers
                sentPacket = static_cast<ZrtpPacketBase *>(parent->currentHelloPacket);

                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();                 // returns to state Initial
                    return;
                }
                if (startTimer(&T1) <= 0) {
                    timerFailed(SevereNoTimer);      // returns to state Initial
                    return;
                }
                return;
            }
            ZrtpPacketHelloAck* helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
                return;
            }
            // Use peer's Hello packet to create my commit packet, store it 
            // for possible later usage in state AckSent
            commitPkt = parent->prepareCommit(&hpkt, &errorCode);

            nextState(AckSent);
            if (commitPkt == NULL) {
                sendErrorPacket(errorCode);    // switches to Error state
                return;
            }
            if (startTimer(&T1) <= 0) {        // restart own Hello timer/counter
                timerFailed(SevereNoTimer);    // returns to state Initial
            }
            T1.maxResend = t1ResendExtend;     // more retries to extend time, see chap. 6
        }
        return;      // unknown packet for this state - Just ignore it
    }
    // Timer event triggered - this is Timer T1 to resend Hello
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();       // returns to state Initial
            return;
        }
        retryCounters[HelloRetry]++;

        if (nextTimer(&T1) <= 0) {
            commitPkt = NULL;
            parent->zrtpNotSuppOther();
            nextState(Detect);
        }
    }
    // If application calls zrtpStart() to restart discovery
    else if (event->type == ZrtpInitial) {
        cancelTimer();
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        if (startTimer(&T1) <= 0) {
            timerFailed(SevereNoTimer);   // returns to state Initial
        }
    }
    else { // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * AckSent state.
 *
 * The protocol engine got a Hello packet from peer and answered with a
 * HelloAck response.  According to the protocol we must also send a 
 * Hello after HelloAck (refer to figure 1 in ZRTP RFC 6189, message
 * HelloACK (F2) must be followed by Hello (F3)). We use the timeout in 
 * this state to send the required Hello (F3).
 *
 * Our peer must acknowledge the Hello with HelloAck. In earlier versions 
 * also a Commit was a valid packet thus the code covers this.
 * Figure 1 in the RFC shows the HelloAck, chapter 7 states that a Commit 
 * may be send to acknowledge Hello. There is one constraint when using a Commit to
 * acknowledge Hello: refer to chapter 4.1 that requires that both parties
 * have completed the Hello/HelloAck discovery handshake. This implies that 
 * only message F4 may be replaced by a Commit. This constraint guarantees
 * that both peers have seen at least one Hello.
 *
 * When entering this transition function:
 * - The instance variabe sentPacket contains own Hello packet
 * - The instance variabe commitPkt points to prepared Commit packet 
 * - Timer T1 is active
 *
 * Possible events in this state are:
 * - timeout for sent Hello packet: causes a resend check and repeat sending
 *   of Hello packet
 * - HelloAck: The peer answered with HelloAck to own HelloAck/Hello. Send
 *   prepared Commit packet and try Initiator mode.
 * - Commit: The peer answered with Commit to HelloAck/Hello, thus switch to
 *   responder mode.
 * - Hello: If the protcol engine receives another Hello it repeats the 
 *   HelloAck/Hello response until Timer T1 exceeds its maximum. This may 
 *   happen if the other peer sends Hello only (maybe due to network problems)
 */
void ZrtpStateClass::evAckSent(void) {

    DEBUGOUT((cout << "Checking for match in AckSent.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    /*
     * First check the general event type, then discrimnate
     * the real event.
     */
    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

        /*
         * HelloAck:
         * The peer answers with HelloAck to own HelloAck/Hello. Send Commit
         * and try Initiator mode. The requirement defined in chapter 4.1 to
         * have a complete Hello/HelloAck is fulfilled.
         * - stop Hello timer T1
         * - send own Commit message
         * - switch state to CommitSent, start Commit timer, assume Initiator
         */
        if (first == 'h' && last =='k') {
            cancelTimer();

            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state CommitSend
            sentPacket = static_cast<ZrtpPacketBase *>(commitPkt);
            commitPkt = NULL;                    // now stored in sentPacket
            nextState(CommitSent);
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
            }
            return;
        }
        /*
         * Hello:
         * - peer didn't receive our HelloAck
         * - repeat HelloAck/Hello response:
         *  -- get HelloAck packet, send it
         *  -- The timeout trigger of T1 sends our Hello packet
         *  -- stay in state AckSent
         *
         * Similar to Detect state: just acknowledge the Hello, the next
         * timeout sends the following Hello.
         */

        if (first == 'h' && last ==' ') {
            ZrtpPacketHelloAck* helloAck = parent->prepareHelloAck();

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                nextState(Detect);
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
            }
            return;
        }
        /*
         * Commit:
         * The peer answers with Commit to HelloAck/Hello, thus switch to
         * responder mode.
         * - stop timer T1
         * - prepare and send our DHPart1
         * - switch to state WaitDHPart2 and wait for peer's DHPart2
         * - don't start timer, we are responder
         */
        if (first == 'c' && last == ' ') {
            cancelTimer();
            ZrtpPacketCommit cpkt(pkt);

            if (!multiStream) {
                ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (dhPart1 == NULL) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                commitPkt = NULL;
                sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);
                nextState(WaitDHPart2);
            }
            else {
                ZrtpPacketConfirm* confirm = parent->prepareConfirm1MultiStream(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (confirm == NULL) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = static_cast<ZrtpPacketBase *>(confirm);
                nextState(WaitConfirm2);
            }
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();      // returns to state Initial
            }
        }
    }
    /*
     * Timer:
     * - resend Hello packet, stay in state, restart timer until repeat
     *   counter triggers
     * - if repeat counter triggers switch to state Detect, con't clear
     *   sentPacket, Detect requires it to point to own Hello message
     */
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            return sendFailed();      // returns to state Initial
        }
        retryCounters[HelloRetryAck]++;

        if (nextTimer(&T1) <= 0) {
            parent->zrtpNotSuppOther();
            commitPkt = NULL;
            // Stay in state Detect to be prepared get an hello from
            // other peer any time later
            nextState(Detect);
        }
    }
    else {   // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        commitPkt = NULL;
        sentPacket = NULL;
        nextState(Initial);
    }
}
/*
 * AckDetected state.
 *
 * The protocol engine received a HelloAck in state Detect, thus the peer 
 * acknowledged our the Hello. According to ZRT RFC 6189 our peer must send
 * its Hello until our protocol engine sees it (refer also to comment for
 * state AckSent). This protocol sequence gurantees that both peers got at
 * least one Hello. 
 *
 * When entering this transition function
 * - instance variable sentPacket is NULL, Hello timer stopped
 *
 * Possible events in this state are:
 * Hello: we have to choices
 *  1) we can acknowledge the peer's Hello with a HelloAck
 *  2) we can acknowledge the peer's Hello with a Commit
 *  Both choices are implemented and may be enabled by setting a compile
 *  time #if (see code below). Currently we use choice 1) here because
 *  it's more aligned to the ZRTP specification
 */
void ZrtpStateClass::evAckDetected(void) {

    DEBUGOUT((cout << "Checking for match in AckDetected.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

#if 1
        /*
         * Implementation for choice 1)
         * Hello:
         * - Acknowledge peer's Hello, sending HelloACK (F4)
         * - switch to state WaitCommit, wait for peer's Commit
         * - we are going to be in the Responder role
         */

        if (first == 'h' && last ==' ') {
            // Parse Hello packet and build an own Commit packet even if the
            // Commit is not send to the peer. We need to do this to check the
            // Hello packet and prepare the shared secret stuff.
            ZrtpPacketHello hpkt(pkt);
            ZrtpPacketCommit* commit = parent->prepareCommit(&hpkt, &errorCode);

            // Something went wrong during processing of the Hello packet, for
            // example wrong version, duplicate ZID.
            if (commit == NULL) {
                sendErrorPacket(errorCode);
                return;
            }
            ZrtpPacketHelloAck *helloAck = parent->prepareHelloAck();
            nextState(WaitCommit);

            // remember packet for easy resend
            sentPacket = static_cast<ZrtpPacketBase *>(helloAck);
            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(helloAck))) {
                sendFailed();
            }
        }
#else
        /*
         * Implementation for choice 2)
         * Hello:
         * - Acknowledge peer's Hello by sending Commit (F5)
         *   instead of HelloAck (F4)
         * - switch to state CommitSent
         * - Initiator role, thus start timer T2 to monitor timeout for Commit
         */

        if (first == 'h' && last == ' ') {
            // Parse peer's packet data into a Hello packet
            ZrtpPacketHello hpkt(pkt);
            ZrtpPacketCommit* commit = parent->prepareCommit(&hpkt, &errorCode);
            // Something went wrong during processing of the Hello packet  
            if (commit == NULL) {
                sendErrorPacket(errorCode);
                return;
            }
            nextState(CommitSent);

            // remember packet for easy resend in case timer triggers
            // Timer trigger received in new state CommitSend
            sentPacket = static_cast<ZrtpPacketBase *>(commit);
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);
            }
        }
#endif
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        nextState(Initial);
    }
}

/*
 * WaitCommit state.
 *
 * This state is only used if we use choice 1) in AckDetected.
 *
 * When entering this transition function
 * - instance variable sentPacket contains a HelloAck packet
 * 
 * Possible events in this state are:
 * - Hello: just resend our HelloAck
 * - Commit: prepare and send our DHPart1 message to start first
 *   half of DH key agreement. Switch to state WaitDHPart2, don't
 *   start any timer, we a Responder.
 */
void ZrtpStateClass::evWaitCommit(void) {

    DEBUGOUT((cout << "Checking for match in WaitCommit.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));
        /*
         * Hello:
         * - resend HelloAck
         * - stay in WaitCommit
         */
        if (first == 'h' && last == ' ') {
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
            }
            return;
        }
        /*
         * Commit:
         * - prepare DH1Part packet or Confirm1 if multi stream mode
         * - send it to peer
         * - switch state to WaitDHPart2 or WaitConfirm2 if multi stream mode
         * - don't start timer, we are responder
         */
        if (first == 'c' && last == ' ') {
            ZrtpPacketCommit cpkt(pkt);

            if (!multiStream) {
                ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (dhPart1 == NULL) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);
                nextState(WaitDHPart2);
            }
            else {
                ZrtpPacketConfirm* confirm = parent->prepareConfirm1MultiStream(&cpkt, &errorCode);

                // Something went wrong during processing of the Commit packet
                if (confirm == NULL) {
                    if (errorCode != IgnorePacket) {
                        sendErrorPacket(errorCode);
                    }
                    return;
                }
                sentPacket = static_cast<ZrtpPacketBase *>(confirm);
                nextState(WaitConfirm2);
            }
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
            }
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * CommitSent state.
 *
 * This state either handles a DH1Part1 message to start the first
 * half of DH key agreement or it handles a Commit clash. If handling a
 * Commit clash it may happen that we change our role from Initiator to
 * Responder.
 *
 * When entering this transition function
 * - assume Initiator mode, may change if we reveice a Commit here
 * - sentPacket contains Commit packet
 * - Commit timer (T2) active
 *
 * Possible events in this state are:
 * - timeout for sent Commit packet: causes a resend check and repeat sending
 *   of Commit packet
 * - Commit: This is a Commit clash. Break the tie accroding to chapter 5.2
 * - DHPart1: start first half of DH key agreement. Perpare and send own DHPart2
 *   and switch to state WaitConfirm1.
 */

void ZrtpStateClass::evCommitSent(void) {

    DEBUGOUT((cout << "Checking for match in CommitSend.\n"));

    char *msg, first, middle, last, secondLast;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        middle = tolower(*(msg+4));
        last = tolower(*(msg+7));
        secondLast = tolower(*(msg+6));

        /*
         * HelloAck or Hello:
         * - delayed "HelloAck" or "Hello", maybe due to network latency, just 
         *   ignore it
         * - no switch in state, leave timer as it is
         */
        if (first == 'h' && middle == 'o' && (last =='k' || last == ' ')) {
            return;
        }

        /*
         * Commit:
         * We have a "Commit" clash. Resolve it.
         *
         * - switch off resending Commit
         * - compare my hvi with peer's hvi
         * - if my hvi is greater
         *   - we are Initiator, stay in state, wait for peer's DHPart1 packet
         * - else
         *   - we are Responder, stop timer
         *   - prepare and send DH1Packt,
         *   - switch to state WaitDHPart2, implies Responder path
         */
        if (first == 'c' && last == ' ') {
            ZrtpPacketCommit zpCo(pkt);

            if (!parent->verifyH2(&zpCo)) {
                return;
            }
            cancelTimer();         // this cancels the Commit timer T2

            if (!zpCo.isLengthOk(multiStream ? ZrtpPacketCommit::MultiStream : ZrtpPacketCommit::DhExchange)) {
                sendErrorPacket(CriticalSWError);
                return;
            }

            // if our hvi is less than peer's hvi: switch to Responder mode and
            // send DHPart1 or Confirm1 packet. Peer (as Initiator) will retrigger if
            // necessary
            //
            if (parent->compareCommit(&zpCo) < 0) {
                if (!multiStream) {
                    ZrtpPacketDHPart* dhPart1 = parent->prepareDHPart1(&zpCo, &errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (dhPart1 == NULL) {
                        if (errorCode != IgnorePacket) {
                            sendErrorPacket(errorCode);
                        }
                        return;
                    }
                    nextState(WaitDHPart2);
                    sentPacket = static_cast<ZrtpPacketBase *>(dhPart1);
                }
                else {
                    ZrtpPacketConfirm* confirm = parent->prepareConfirm1MultiStream(&zpCo, &errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (confirm == NULL) {
                        if (errorCode != IgnorePacket) {
                            sendErrorPacket(errorCode);
                        }
                        return;
                    }
                    nextState(WaitConfirm2);
                    sentPacket = static_cast<ZrtpPacketBase *>(confirm);
                }
                if (!parent->sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
            }
            // Stay in state, we are Initiator, wait for DHPart1 of Confirm1 packet from peer.
            // Resend Commit after timeout until we get a DHPart1 or Confirm1
            else {
                if (startTimer(&T2) <= 0) { // restart the Commit timer, gives peer more time to react
                    timerFailed(SevereNoTimer);    // returns to state Initial
                }
            }
            return;
        }

        /*
         * DHPart1:
         * - switch off resending Commit
         * - Prepare and send DHPart2
         * - switch to WaitConfirm1
         * - start timer to resend DHPart2 if necessary, we are Initiator
         */
        if (first == 'd' && secondLast == '1') {
            cancelTimer();
            sentPacket = NULL;
            ZrtpPacketDHPart dpkt(pkt);
            ZrtpPacketDHPart* dhPart2 = parent->prepareDHPart2(&dpkt, &errorCode);

            // Something went wrong during processing of the DHPart1 packet
            if (dhPart2 == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
                else {
                    if (startTimer(&T2) <= 0) {
                        timerFailed(SevereNoTimer);       // switches to state Initial
                    }
                }

                return;
            }
            sentPacket = static_cast<ZrtpPacketBase *>(dhPart2);
            nextState(WaitConfirm1);

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);       // switches to state Initial
            }
            return;
        }

        /*
         * Confirm1 and multi-stream mode
         * - switch off resending commit
         * - prepare Confirm2
         */
        if (multiStream && (first == 'c' && last == '1')) {
            cancelTimer();
            ZrtpPacketConfirm cpkt(pkt);

            ZrtpPacketConfirm* confirm = parent->prepareConfirm2MultiStream(&cpkt, &errorCode);

            // Something went wrong during processing of the Confirm1 packet
            if (confirm == NULL) {
                sendErrorPacket(errorCode);
                return;
            }
            nextState(WaitConfAck);
            sentPacket = static_cast<ZrtpPacketBase *>(confirm);

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();         // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
                return;
            }
            // according to chap 5.6: after sending Confirm2 the Initiator must
            // be ready to receive SRTP data. SRTP sender will be enabled in WaitConfAck
            // state.
            if (!parent->srtpSecretsReady(ForReceiver)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
        }
    }
    // Timer event triggered, resend the Commit packet
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
                return;
        }
        retryCounters[CommitRetry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);       // returns to state Initial
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * WaitDHPart2 state.
 *
 * This state handles the second part of SH key agreement. Only the Resonder
 * can enter this state.
 *
 * When entering this transition function
 * - sentPacket contains DHPart1 packet, no timer active
 *
 * Possible events in this state are:
 * - Commit: Our peer didn't receive out DHPart1 thus the peer sends Commit again.
 *   Just repeat our DHPart1.
 * - DHPart2: start second half of DH key agreement. Perpare and send own Confirm1
 *   and switch to state WaitConfirm2.
 */
void ZrtpStateClass::evWaitDHPart2(void) {

    DEBUGOUT((cout << "Checking for match in DHPart2.\n"));

    char *msg, first, secondLast, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));
        secondLast = tolower(*(msg+6));
        /*
         * Commit:
         * - resend DHPart1
         * - stay in state
         */
        if (first == 'c' && last == ' ') {
            if (!parent->sendPacketZRTP(sentPacket)) {
                return sendFailed();       // returns to state Initial
            }
            return;
        }
        /*
         * DHPart2:
         * - prepare Confirm1 packet
         * - switch to WaitConfirm2
         * - No timer, we are responder
         */
        if (first == 'd' && secondLast == '2') {
            ZrtpPacketDHPart dpkt(pkt);
            ZrtpPacketConfirm* confirm = parent->prepareConfirm1(&dpkt, &errorCode);

            if (confirm == NULL) {
                if (errorCode != IgnorePacket) {
                    sendErrorPacket(errorCode);
                }
                return;
            }
            nextState(WaitConfirm2);
            sentPacket = static_cast<ZrtpPacketBase *>(confirm);
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();       // returns to state Initial
            }
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * WaitConirm1 state.
 *
 * This state handles a received Confirm1 message and only the Initiator
 * can enter this state.
 *
 * When entering this transition function in DH mode:
 * - Initiator mode
 * - sentPacket contains DHPart2 packet, DHPart2 timer active
 *
 * When entering this transition function in Multi stream mode via AckSent:
 * - Initiator mode
 * - sentPacket contains my Commit packet, Commit timer active
 * 
* Possible events in this state are:
 * - timeout for sent DHPart2 packet: causes a resend check and repeat sending
 *   of DHPart2 packet.
 * - Confirm1: Check Confirm1 message. If it is ok then prepare and send own
 *   Confirm2 packet and switch to state WaitConfAck.
 */
void ZrtpStateClass::evWaitConfirm1(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfirm1.\n"));

    char *msg, first, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

        /*
         * Confirm1:
         * - Switch off resending DHPart2
         * - prepare a Confirm2 packet
         * - switch to state WaitConfAck
         * - set timer to monitor Confirm2 packet, we are initiator
         */
        if (first == 'c' && last == '1') {
            cancelTimer();
            ZrtpPacketConfirm cpkt(pkt);

            ZrtpPacketConfirm* confirm = parent->prepareConfirm2(&cpkt, &errorCode);

            // Something went wrong during processing of the Confirm1 packet
            if (confirm == NULL) {
                sendErrorPacket(errorCode);
                return;
            }
            // according to chap 5.8: after sending Confirm2 the Initiator must
            // be ready to receive SRTP data. SRTP sender will be enabled in WaitConfAck
            // state.
            if (!parent->srtpSecretsReady(ForReceiver)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(WaitConfAck);
            sentPacket = static_cast<ZrtpPacketBase *>(confirm);

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();         // returns to state Initial
                return;
            }
            if (startTimer(&T2) <= 0) {
                timerFailed(SevereNoTimer);  // returns to state Initial
            }
        }
    }
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();             // returns to state Initial
            return;
        }
        retryCounters[DhPart2Retry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);     // returns to state Initial
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * WaitConfirm2 state.
 *
 * Handles the Confirm2 message that closes the key agreement handshake. Only
 * the Responder can enter this state. If the Confirm2 message is ok send a 
 * Conf2Ack to our peer. Switch to secure mode after sending Conf2Ack, our 
 * peer switches to secure mode after receiving Conf2Ack.
 *
 * TODO - revise documentation comments
 * 
 * When entering this transition function
 * - Responder mode
 * - sentPacket contains Confirm1 packet, no timer active
 *
 * Possible events in this state are:
 * - DHPart2: Our peer didn't receive our Confirm1 thus sends DHPart2 again.
 *   Just repeat our Confirm1.
 * - Confirm2: close DH key agreement. Perpare and send own Conf2Ack
 *   and switch to state SecureState.
 */
void ZrtpStateClass::evWaitConfirm2(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfirm2.\n"));

    char *msg, first, secondLast, last;
    uint8_t *pkt;
    uint32_t errorCode = 0;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        secondLast = tolower(*(msg+6));
        last = tolower(*(msg+7));

        /*
         * DHPart2 or Commit in multi stream mode:
         * - resend Confirm1 packet
         * - stay in state
         */
        if ((first == 'd' && secondLast == '2') || (multiStream && (first == 'c' && last == ' '))) {
            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
            }
            return;
        }
        /*
         * Confirm2:
         * - prepare ConfAck
         * - switch on security (SRTP)
         * - switch to SecureState
         */
        if (first == 'c' && last == '2') {
            ZrtpPacketConfirm cpkt(pkt);
            ZrtpPacketConf2Ack* confack = parent->prepareConf2Ack(&cpkt, &errorCode);

            // Something went wrong during processing of the confirm2 packet
            if (confack == NULL) {
                sendErrorPacket(errorCode);
                return;
            }
            sentPacket = static_cast<ZrtpPacketBase *>(confack);

            if (!parent->sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
                return;
            }
            if (!parent->srtpSecretsReady(ForReceiver) || !parent->srtpSecretsReady(ForSender))  {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(SecureState);
            parent->sendInfo(Info, InfoSecureStateOn);
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

/*
 * WaitConf2Ack state.
 *
 * This state handles the Conf2Ack message that acknowledges the successfull
 * processing of Confirm2. Only the Initiator can enter this state. Switch on
 * secure mode and switch to state SecureState.
 *
 * When entering this transition function
 * - Initiator mode
 * - sentPacket contains Confirm2 packet, Confirm2 timer active
 * - receiver security switched on
 *
 * Possible events in this state are:
 * - timeout for sent Confirm2 packet: causes a resend check and repeat sending
 *   of Confirm2 packet
 * - Conf2Ack: Key agreement was successfull, switch to secure mode.
 */
void ZrtpStateClass::evWaitConfAck(void) {

    DEBUGOUT((cout << "Checking for match in WaitConfAck.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));
         /*
         * ConfAck:
         * - Switch off resending Confirm2
         * - switch to SecureState
         */
        if (first == 'c' && last == 'k') {
            cancelTimer();
            sentPacket = NULL;
            // Receiver was already enabled after sending Confirm2 packet
            // see previous states.
            if (!parent->srtpSecretsReady(ForSender)) {
                parent->sendInfo(Severe, CriticalSWError);
                sendErrorPacket(CriticalSWError);
                return;
            }
            nextState(SecureState);
            // TODO: call parent to clear signature data at initiator
            parent->sendInfo(Info, InfoSecureStateOn);
        }
    }
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();             // returns to state Initial
            parent->srtpSecretsOff(ForReceiver);
            return;
        }
        retryCounters[Confirm2Retry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries); // returns to state Initial
            parent->srtpSecretsOff(ForReceiver);
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
        parent->srtpSecretsOff(ForReceiver);
    }
}

/*
 * When entering this transition function
 * - sentPacket contains GoClear packet, GoClear timer active
 */

void ZrtpStateClass::evWaitClearAck(void) {
    DEBUGOUT((cout << "Checking for match in ClearAck.\n"));

//     char *msg, first, last, middle;
//     uint8_t *pkt;
// 
//     if (event->type == ZrtpPacket) {
// 	pkt = event->packet;
// 	msg = (char *)pkt + 4;
// 
// 	first = tolower(*msg);
//     middle = tolower(*(msg+4));
// 	last = tolower(*(msg+7));
// 
// 	/*
// 	 * ClearAck:
// 	 * - stop resending GoClear,
// 	 * - switch to state AckDetected, wait for peer's Hello
// 	 */
// 	if (first == 'c' && middle == 'r' && last =='k') {
// 	    cancelTimer();
// 	    sentPacket = NULL;
// 	    nextState(Initial);
// 	}
//     }
//     // Timer event triggered - this is Timer T2 to resend GoClear w/o HMAC
//     else if (event->type == Timer) {
//         if (!parent->sendPacketZRTP(sentPacket)) {
//             sendFailed();                 // returns to state Initial
//             return;
//         }
//         if (nextTimer(&T2) <= 0) {
//             timerFailed(SevereTooMuchRetries);     // returns to state Initial
//         }
//     }
//     else {  // unknown Event type for this state (covers Error and ZrtpClose)
//         if (event->type != ZrtpClose) {
//             parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
//         }
// 	sentPacket = NULL;
// 	nextState(Initial);
//     }
}


/*
 * WaitErrorAck state.
 *
 * This state belongs to the "error handling state overlay" and handle
 * ErrorAck message. Most of the ZRTP states can send Error message for
 * example if they detect wrong packets. After sending an Error message
 * the protocol engine switches to WaitErrorAck state. Receiving an
 * ErrorAck message completes the ZRTP error handling.
 *
 * When entering this transition function
 * - sentPacket contains Error packet, Error timer active
 *
 * Possible events in this state are:
 * - timeout for sent Error packet: causes a resend check and repeat sending
 *   of Error packet
 * - ErrorAck: Stop timer and switch to state Initial.
 */

void ZrtpStateClass::evWaitErrorAck(void) {
    DEBUGOUT((cout << "Checking for match in ErrorAck.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

        /*
         * Errorck:
         * - stop resending Error,
         * - switch to state Initial
         */
        if (first == 'e' && last =='k') {
            cancelTimer();
            sentPacket = NULL;
            nextState(Initial);
        }
    }
    // Timer event triggered - this is Timer T2 to resend Error.
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed();                 // returns to state Initial
            return;
        }
        retryCounters[ErrorRetry]++;

        if (nextTimer(&T2) <= 0) {
            timerFailed(SevereTooMuchRetries);     // returns to state Initial
        }
    }
    else {  // unknown Event type for this state (covers Error and ZrtpClose)
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        sentPacket = NULL;
        nextState(Initial);
    }
}

void ZrtpStateClass::evSecureState(void) {

    DEBUGOUT((cout << "Checking for match in SecureState.\n"));

    char *msg, first, last;
    uint8_t *pkt;

    /*
     * Handle a possible substate. If substate handling was ok just return.
     */
    if (secSubstate == WaitSasRelayAck) {
        if (subEvWaitRelayAck())
            return; 
    }

    if (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

        /*
         * Confirm2:
         * - resend Conf2Ack packet
         * - stay in state
         */
        if (first == 'c' && last == '2') {
            if (sentPacket != NULL && !parent->sendPacketZRTP(sentPacket)) {
                sentPacket = NULL;
                nextState(Initial);
                parent->srtpSecretsOff(ForSender);
                parent->srtpSecretsOff(ForReceiver);
                parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
            }
            return;
        }
        /*
         * GoClear received, handle it. TODO fix go clear handling
         *
        if (first == 'g' && last == 'r') {
            ZrtpPacketGoClear gpkt(pkt);
            ZrtpPacketClearAck* clearAck = parent->prepareClearAck(&gpkt);

            if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(clearAck))) {
                return;
            }
        // TODO Timeout to resend clear ack until user user confirmation
        }
        */
    }
    else if (event->type == Timer) {
        // Ignore stray timeout in this state
        ;
    }
    // unknown Event type for this state (covers Error and ZrtpClose)
    else  {
        // If in secure state ingnore error events to avoid Error packet injection
        // attack - found by Dmitry Monakhov (dmonakhov@openvz.org)
        if (event->type == ErrorPkt)
            return;
        sentPacket = NULL;
        parent->srtpSecretsOff(ForSender);
        parent->srtpSecretsOff(ForReceiver);
        nextState(Initial);
        if (event->type != ZrtpClose) {
            parent->zrtpNegotiationFailed(Severe, SevereProtocolError);
        }
        parent->sendInfo(Info, InfoSecureStateOff);
    }
}

bool ZrtpStateClass::subEvWaitRelayAck() {
    char *msg, first, last;
    uint8_t* pkt;

    /*
     * First check the general event type, then discrimnate the real event.
     */
    if  (event->type == ZrtpPacket) {
        pkt = event->packet;
        msg = (char *)pkt + 4;

        first = tolower(*msg);
        last = tolower(*(msg+7));

        /*
         * SAS relayAck:
         * - stop resending SASRelay,
         * - switch to secure substate Normal
         */
        if (first == 'r' && last =='k') {
            cancelTimer();
            secSubstate = Normal;
            sentPacket = NULL;
        }
        return true;
    }
    // Timer event triggered - this is Timer T2 to resend Error.
    else if (event->type == Timer) {
        if (!parent->sendPacketZRTP(sentPacket)) {
            sendFailed(); // returns to state Initial
            return false;
        }
        if (nextTimer(&T2) <= 0) {
            // returns to state initial
            // timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);
            return false;
        }
        return true;
    }
    return false;
}

int32_t ZrtpStateClass::startTimer(zrtpTimer_t *t) {

    t->time = t->start;
    t->counter = 0;
    return parent->activateTimer(t->time);
}

int32_t ZrtpStateClass::nextTimer(zrtpTimer_t *t) {

    t->time += t->time;
    t->time = (t->time > t->capping)? t->capping : t->time;
    if (t->maxResend > 0) {
        t->counter++;
        if (t->counter > t->maxResend) {
            return -1;
        }
    }
    return parent->activateTimer(t->time);
}

void ZrtpStateClass::sendErrorPacket(uint32_t errorCode) {
    cancelTimer();

    ZrtpPacketError* err = parent->prepareError(errorCode);
    parent->zrtpNegotiationFailed(ZrtpError, errorCode);

    sentPacket =  static_cast<ZrtpPacketBase *>(err);
    nextState(WaitErrorAck);
    if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(err)) || (startTimer(&T2) <= 0)) {
        sendFailed();
    }
}

void ZrtpStateClass::sendSASRelay(ZrtpPacketSASrelay* relay) {
    cancelTimer();
    sentPacket = static_cast<ZrtpPacketBase *>(relay);
    secSubstate = WaitSasRelayAck;
    if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(relay)) || (startTimer(&T2) <= 0)) {
        sendFailed();
    }
}

void ZrtpStateClass::sendFailed() {
    sentPacket = NULL;
    nextState(Initial);
    parent->zrtpNegotiationFailed(Severe, SevereCannotSend);
}

void ZrtpStateClass::timerFailed(int32_t subCode) {
    sentPacket = NULL;
    nextState(Initial);
    parent->zrtpNegotiationFailed(Severe, subCode);
}

void ZrtpStateClass::setMultiStream(bool multi) {
    multiStream = multi;
}

bool ZrtpStateClass::isMultiStream() {
    return multiStream;
}


int ZrtpStateClass::getNumberOfRetryCounters() {
    return sizeof(retryCounters)/sizeof(int32_t);
}

int ZrtpStateClass::getRetryCounters(int32_t* counters) {
    memcpy(counters, retryCounters, sizeof(retryCounters));
    return sizeof(retryCounters)/sizeof(int32_t);
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */

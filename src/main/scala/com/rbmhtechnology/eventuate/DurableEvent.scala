/*
 * Copyright (C) 2015 Red Bull Media House GmbH <http://www.redbullmediahouse.com> - all rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.rbmhtechnology.eventuate

import DurableEvent._

/**
 * Provider API.
 *
 * Event storage format.
 *
 * @param payload Application-defined event.
 * @param emitterId Id of emitter ([[EventsourcedActor]]).
 * @param emitterAggregateId Aggregate id of emitter ([[EventsourcedActor]]). This is also the default routing destination
 *                           of this event. If defined, the event is routed to event-sourced actors or views with a matching
 *                           `aggregateId`. In any case, the event is routed to event-sourced actors and views with an
 *                           undefined `aggregateId`.
 * @param customDestinationAggregateIds Aggregate ids of additional, custom routing destinations. If non-empty, the event is
 *                                      additionally routed to event-sourced actors and views with a matching `aggregateId`.
 * @param systemTimestamp Wall-clock timestamp, generated by the source of concurrent activity that is identified by `processId`.
 * @param vectorTimestamp Vector timestamp, generated by the source of concurrent activity that is identified by `processId`.
 * @param processId Id of the causality-tracking source of concurrent activity. By default, this is the id of the event log
 *                  that initially wrote the event. If the emitting [[EventsourcedActor]] has set `sharedClockEntry` to `false`
 *                  then this is the id of that actor (which is the `emitterId`).
 * @param sourceLogId Id of the source log from last replication. Equals to `targetLogId` if not replicated yet.
 * @param targetLogId Id of the target log from last replication.
 * @param sourceLogSequenceNr Sequence number in source log from last replication.
 * @param targetLogSequenceNr Sequence number in target log from last replication.
 * @param sourceLogReadPosition Highest source log read position from last replication.
 */
case class DurableEvent(
  payload: Any,
  emitterId: String,
  emitterAggregateId: Option[String] = None,
  customDestinationAggregateIds: Set[String] = Set(),
  systemTimestamp: Long = 0L,
  vectorTimestamp: VectorTime = VectorTime(),
  processId: String = UndefinedLogId,
  sourceLogId: String = UndefinedLogId,
  targetLogId: String = UndefinedLogId,
  sourceLogSequenceNr: Long = UndefinedSequenceNr,
  targetLogSequenceNr: Long = UndefinedSequenceNr,
  sourceLogReadPosition: Long = 0L) {

  /**
   * Unique event identifier.
   */
  def id: VectorTime =
    vectorTimestamp

  /**
   * Local logId (= `targetLogId`).
   */
  def logId: String =
    targetLogId

  /**
   * Local sequence number (= `targetLogSequenceNr`).
   */
  def sequenceNr: Long =
    targetLogSequenceNr

  /**
   * `true` if this is a replicated event.
   */
  def replicated: Boolean =
    targetLogId != sourceLogId

  /**
   * The default routing destination of this event is its `emitterAggregateId`. If defined, the event is
   * routed to event-sourced actors and views with a matching `aggregateId`. In any case, the event is
   * routed to event-sourced actors and views with an undefined `aggregateId`.
   */
  def defaultDestinationAggregateId: Option[String] =
    emitterAggregateId

  /**
   * The union of [[defaultDestinationAggregateId]] and [[customDestinationAggregateIds]].
   */
  def destinationAggregateIds: Set[String] =
    if (defaultDestinationAggregateId.isDefined) customDestinationAggregateIds + defaultDestinationAggregateId.get else customDestinationAggregateIds
}

object DurableEvent {
  val UndefinedLogId = ""
  val UndefinedSequenceNr = 0L

  def apply(emitterId: String): DurableEvent =
    DurableEvent(payload = null, emitterId)
}

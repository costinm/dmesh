package com.github.costinm.dmesh.wifi;

/** Terminal state of one immutable transport.start epoch. */
public final class TransportResult {
    public enum Outcome { APPLIED, UNCHANGED, ERROR }
    public final Outcome outcome;
    public final String correlationId;
    public final long generation;
    public final String state;
    public final String error;
    /** Whether the ingress bearer survived long enough for its response. */
    public final boolean replyTransportAvailable;
    /** True when a failed replacement restored the previous stable epoch. */
    public final boolean previousTransportRestored;

    public TransportResult(Outcome outcome, String correlationId, long generation,
                           String state, String error, boolean replyTransportAvailable,
                           boolean previousTransportRestored) {
        this.outcome = outcome;
        this.correlationId = correlationId;
        this.generation = generation;
        this.state = state;
        this.error = error;
        this.replyTransportAvailable = replyTransportAvailable;
        this.previousTransportRestored = previousTransportRestored;
    }
}

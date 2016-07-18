/*
 * Copyright 2016 E.Hooijmeijer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.ctrlaltdev.harbinger.evidence;

import java.time.Duration;
import java.time.Instant;

public class EvidenceAggregation {

    private Instant first = null;
    private Instant last = null;
    private long numberOfRequests = 0;
    private long http2xx = 0;
    private long http3xx = 0;
    private long http4xx = 0;
    private long http5xx = 0;
    private long exceptions = 0;
    private long detections = 0;

    public EvidenceAggregation(Evidence ev) {
        this.first = ev.getTimestamp();
        this.last = ev.getTimestamp();
        score(ev);
    }

    public EvidenceAggregation(EvidenceAggregation parent) {
        this.first = parent.first;
        this.numberOfRequests = parent.numberOfRequests;
        this.http2xx = parent.http2xx;
        this.http3xx = parent.http3xx;
        this.http4xx = parent.http4xx;
        this.http5xx = parent.http5xx;
        this.exceptions = parent.exceptions;
        this.detections = parent.detections;
    }

    public EvidenceAggregation(EvidenceAggregation parent, Evidence ev) {
        this(parent);
        this.last = ev.getTimestamp();
        score(ev);
    }

    private void score(Evidence ev) {
        if (ev.getExceptionType() != null) {
            exceptions++;
        }
        if (ev.getRule() != null) {
            detections += ev.getRule().getLevel().getScore();
        }
        if (ev.getStatusCode() > 0) {
            numberOfRequests++;
            if (ev.getStatusCode() >= 500) {
                http5xx++;
            } else if (ev.getStatusCode() >= 400) {
                http4xx++;
            } else if (ev.getStatusCode() >= 300) {
                http3xx++;
            } else if (ev.getStatusCode() >= 200) {
                http2xx++;
            }
        }
    }

    public Instant getFirst() {
        return first;
    }

    public Instant getLast() {
        return last;
    }

    public long getDetections() {
        return detections;
    }

    public long getExceptions() {
        return exceptions;
    }

    public long getHttp2xx() {
        return http2xx;
    }

    public long getHttp3xx() {
        return http3xx;
    }

    public long getHttp4xx() {
        return http4xx;
    }

    public long getHttp5xx() {
        return http5xx;
    }

    public long getNumberOfRequests() {
        return numberOfRequests;
    }

    /**
     * @param ref the reference timestamp.
     * @return if the last evidence is before the reference timestamp.
     */
    public boolean isOld(Instant ref) {
        return last.isBefore(ref);
    }

    /**
     * @param minPeriod the minimum period in ms.
     * @return the average number of requests or 0 if the minimum period has not expired.
     */
    public int getAverageRpS(long minPeriod) {
        Duration delta = Duration.between(first, last);
        if (!delta.minusMillis(minPeriod).isNegative()) {
            return Math.round(numberOfRequests / delta.getSeconds());
        } else {
            return 0;
        }
    }
}

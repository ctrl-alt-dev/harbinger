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
package nl.ctrlaltdev.harbinger.response;

import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.evidence.EvidenceAggregation;
import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.rule.DetectionRule.Level;
import nl.ctrlaltdev.harbinger.whitelist.WhiteList;
import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListBuilder;

public class SimpleResponseDecider implements ResponseDecider {

    private static final NoAction NOACTION = new NoAction();
    private static final InvalidateSessionAction INVALIDATE_SESSION = new InvalidateSessionAction();
    private static final RejectInputAction REJECT_RESPONSE = new RejectInputAction();

    private EvidenceCollector collector;
    private long sessionThreshold;
    private long ipThreshold;
    private WhiteList whiteList;

    public SimpleResponseDecider(EvidenceCollector coll) {
        this(coll, 42L, 128L, WhiteListBuilder.empty());
    }

    public SimpleResponseDecider(EvidenceCollector coll, long sessionThreshold, long ipThreshold, WhiteList whiteList) {
        this.collector = coll;
        this.sessionThreshold = sessionThreshold;
        this.ipThreshold = ipThreshold;
        this.whiteList = whiteList;
    }

    @Override
    public ResponseAction decide(Evidence ev) {
        if (whiteList.isWhitelisted(ev)) {
            return NOACTION;
        }
        if (ev.getSession() != null) {
            if (score(collector.findBySession(ev)) >= sessionThreshold) {
                return INVALIDATE_SESSION;
            }
        }
        if (ev.getIp() != null) {
            if (score(collector.findByIp(ev)) >= ipThreshold) {
                return new BlacklistIpAction(ev, 5);
            }
        }
        if (score(collector.single(ev)) >= Level.HIGH.getScore()) {
            return REJECT_RESPONSE;
        }
        return NOACTION;
    }

    private long score(EvidenceAggregation agg) {
        long score = 0;
        score += agg.getDetections();
        score += agg.getHttp5xx();
        score += (agg.getAverageRpS(30000L) > 2) ? 25 : 0;
        return score;
    }

}

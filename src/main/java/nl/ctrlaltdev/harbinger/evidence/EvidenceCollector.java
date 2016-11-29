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

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import nl.ctrlaltdev.harbinger.whitelist.WhiteList;
import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListBuilder;

public class EvidenceCollector {

    private Logger LOGGER = LoggerFactory.getLogger(getClass());

    private WhiteList whiteList;

    private Map<String, EvidenceAggregation> evidenceByIp;
    private Map<String, EvidenceAggregation> evidenceBySession;

    public EvidenceCollector() {
        this(WhiteListBuilder.empty());
    }

    public EvidenceCollector(WhiteList whiteList) {
        this.whiteList = whiteList;
        this.evidenceByIp = new ConcurrentHashMap<>();
        this.evidenceBySession = new ConcurrentHashMap<>();
    }

    public Evidence enhanceAndStore(Evidence evidence) {
        return store(enhance(evidence));
    }

    private Evidence enhance(Evidence evidence) {
        if (evidence.getIp() == null) {
            ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (sra != null) {
                evidence = new Evidence(evidence, sra.getRequest());
            }
        }
        if (evidence.getUser() == null) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null) {
                evidence = new Evidence(evidence, auth);
            }
        }
        return evidence;
    }

    /**
     * Stores evidence temporarily.
     * @param evidence the evidence.
     * @return the aggregated evidence.
     */
    public Evidence store(Evidence evidence) {
        if (isWarning(evidence)) {
            LOGGER.warn(evidence.toString());
        }
        if (whiteList.isWhitelisted(evidence)) {
            LOGGER.info("Ignoring whitelisted evidence.");
            return new Evidence();
        }
        if (evidence.getIp() != null) {
            store(evidenceByIp, evidence.getIp(), evidence);
        }
        if (evidence.getSession() != null) {
            store(evidenceBySession, evidence.getSession(), evidence);
        }
        return evidence;
    }

    private boolean isWarning(Evidence evidence) {
        return (evidence.getStatusCode() >= 400) || (evidence.getExceptionType() != null) || (evidence.getRule() != null);
    }

    private EvidenceAggregation store(Map<String, EvidenceAggregation> store, String id, Evidence evidence) {
        EvidenceAggregation aggr = store.get(id);
        if (aggr == null) {
            aggr = new EvidenceAggregation(evidence);
            store.put(id, aggr);
        } else {
            aggr = new EvidenceAggregation(aggr, evidence);
            store.put(id, aggr);
        }
        return aggr;
    }

    /**
     * Finds the evidenceAggregation by IP.
     * @param ev the evidence that holds the ip you're looking for.
     * @return the evidenceAggregation by ip.
     */
    public EvidenceAggregation findByIp(Evidence ev) {
        EvidenceAggregation defaultValue = new EvidenceAggregation(ev);
        if (ev.getIp() == null) {
            return defaultValue;
        } else {
            return evidenceByIp.getOrDefault(ev.getIp(), defaultValue);
        }
    }

    /**
     * Finds the eveidenceAggregation by sessionId.
     * @param ev the evidence that holds the session you're looking for.
     * @return the evidence by session.
     */
    public EvidenceAggregation findBySession(Evidence ev) {
        EvidenceAggregation defaultValue = new EvidenceAggregation(ev);
        if (ev.getSession() == null) {
            return defaultValue;
        } else {
            return evidenceBySession.getOrDefault(ev.getSession(), defaultValue);
        }
    }

    public EvidenceAggregation single(Evidence ev) {
        return new EvidenceAggregation(ev);
    }

    /**
     * Cleans up any evidence from memory with a timestamp before ref.
     * @param ref the reference timestamp.
     */
    public void clean(Instant ref) {
        clean(evidenceByIp, ref);
        clean(evidenceBySession, ref);
    }

    private void clean(Map<String, EvidenceAggregation> store, Instant ref) {
        for (Map.Entry<String, EvidenceAggregation> entry : store.entrySet()) {
            EvidenceAggregation evidence = entry.getValue();
            if (evidence.isOld(ref)) {
                store.remove(entry.getKey());
            }
        }
    }
    
    /**
     * Cleans up the evidence store for the given evidence. Useful to prevent
     * blacklist loops.
     * @param ev the evidence to forget.
     */
    public void clean(Evidence ev) {
        if (ev.getIp()!=null) {
            evidenceByIp.remove(ev.getIp());
        }
        if (ev.getSession()!=null) {
            evidenceBySession.remove(ev.getSession());
        }
    }
}

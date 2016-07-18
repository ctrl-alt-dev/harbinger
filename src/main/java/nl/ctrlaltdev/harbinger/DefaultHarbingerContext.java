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
package nl.ctrlaltdev.harbinger;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.response.ResponseDecider;
import nl.ctrlaltdev.harbinger.response.SimpleResponseDecider;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;

/**
 * 
 */
public class DefaultHarbingerContext implements HarbingerContext {

    protected static final Logger LOGGER = LoggerFactory.getLogger(DefaultHarbingerContext.class);

    private Map<String, Instant> ipBlacklist = new ConcurrentHashMap<>();
    private Set<DetectionRule> rules = new HashSet<>();
    private EvidenceCollector collector;

    private ResponseDecider responseDecider;

    public DefaultHarbingerContext(Set<DetectionRule> rules) {
        this(rules, new EvidenceCollector());
    }

    public DefaultHarbingerContext(Set<DetectionRule> rules, EvidenceCollector collector) {
        this(rules, collector, new SimpleResponseDecider(collector));
    }

    public DefaultHarbingerContext(Set<DetectionRule> rules, EvidenceCollector collector, ResponseDecider decider) {
        this.rules = rules;
        this.collector = collector;
        this.responseDecider = decider;
    }

    @Override
    public EvidenceCollector getEvidenceCollector() {
        return collector;
    }

    public ResponseDecider getResponseDecider() {
        return responseDecider;
    }

    @Override
    public boolean isValid(String value) {
        if (value == null) {
            return true;
        }
        Evidence evidence = null;
        value = normalize(value);
        for (DetectionRule rule : rules) {
            if (rule.matches(value)) {
                evidence = new Evidence(new Evidence(), rule, value);
                break;
            }
        }
        if (evidence != null) {
            return responseDecider.decide(collector.enhanceAndStore(evidence)).perform(this);
        }
        return true;
    }

    @Override
    public void blacklist(String remoteAddr, Instant until) {
        LOGGER.warn("Blacklisting {} until {}", filterForLog(remoteAddr), until);
        ipBlacklist.put(remoteAddr, until);
    }

    @Override
    public boolean isBlacklisted(String remoteAddr, Instant now) {
        Instant until = ipBlacklist.get(remoteAddr);
        if (until == null) {
            return false;
        } else if (!until.isAfter(now)) {
            LOGGER.warn("Blacklist for {} expired", filterForLog(remoteAddr));
            ipBlacklist.remove(remoteAddr);
            return false;
        } else {
            return true;
        }
    }

    public static final String filterForLog(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int t = 0; t < value.length(); t++) {
            char c = value.charAt(t);
            if (!Character.isISOControl(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String normalize(String value) {
        return urldecode(value).toLowerCase();
    }

    private String urldecode(String str) {
        if (str.indexOf('%') >= 0) {
            try {
                return URLDecoder.decode(str, "UTF-8");
            } catch (UnsupportedEncodingException | IllegalArgumentException ex) {
                return str;
            }
        } else {
            return str;
        }
    }

}

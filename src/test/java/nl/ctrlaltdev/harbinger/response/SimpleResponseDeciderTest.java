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

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.whitelist.WhiteList;
import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListBuilder;

public class SimpleResponseDeciderTest {

    private EvidenceCollector coll = new EvidenceCollector();
    private WhiteList emptyWhiteList = WhiteListBuilder.empty();
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private DetectionRule rule = new DetectionRule(new String[] { "Bad", "HIGH", "" });
    private Evidence ev = new Evidence(request);

    @Test
    public void shouldDecideNoAction() {
        SimpleResponseDecider decider = new SimpleResponseDecider(coll, 1, 1, emptyWhiteList);

        assertTrue(decider.decide(ev) instanceof NoAction);
    }

    @Test
    public void shouldDecideBlacklistIPAction() {
        coll.store(new Evidence(ev, rule, ""));
        SimpleResponseDecider decider = new SimpleResponseDecider(coll, 1, 1, emptyWhiteList);
        assertTrue(decider.decide(ev) instanceof BlacklistIpAction);
    }

    @Test
    public void shouldDecideInvalidateSessionAction() {
        request.getSession(true);
        Evidence evidence = new Evidence(new Evidence(request), rule, "");
        coll.store(evidence);

        SimpleResponseDecider decider = new SimpleResponseDecider(coll, 1, 1, emptyWhiteList);
        assertTrue(decider.decide(evidence) instanceof InvalidateSessionAction);
    }

    @Test
    public void shouldDecideRejectInputAction() {
        Evidence evidence = new Evidence(new Evidence(), rule, "");
        coll.store(evidence);

        SimpleResponseDecider decider = new SimpleResponseDecider(coll, 1, 1, emptyWhiteList);
        assertTrue(decider.decide(evidence) instanceof RejectInputAction);
    }

    @Test
    public void shouldTakeNoActionOnWhitelistedRequests() {
        coll.store(new Evidence(ev, rule, ""));
        WhiteList whitelist = WhiteListBuilder.create().ip("127.0.0.1").build();
        SimpleResponseDecider decider = new SimpleResponseDecider(coll, 1, 1, whitelist);
        assertTrue(decider.decide(ev) instanceof NoAction);
    }

}

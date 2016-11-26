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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;
import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;

public class BlacklistIpActionTest {

    private HarbingerContext ctx = new DefaultHarbingerContext(Collections.emptySet());
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private BlacklistIpAction action;

    @Before
    public void init() {
        request.setRemoteAddr("8.8.8.8");
        Evidence ev = new Evidence(request);
        action = new BlacklistIpAction(ev, 1);
    }

    @Test
    public void shouldBlacklist() {
        assertTrue(action.perform(ctx));
        assertTrue(ctx.isBlacklisted("8.8.8.8", Instant.now()));
        assertFalse(ctx.isBlacklisted("8.8.8.8", Instant.now().plusSeconds(61)));
    }

    @Test
    public void shouldCleanEvidenceAfterBlacklisting() {
        Evidence src = new Evidence(request);
        Evidence trigger = new Evidence(src, new RuntimeException());
        ctx.getEvidenceCollector().store(trigger);
        assertEquals(1, ctx.getEvidenceCollector().findByIp(trigger).getExceptions());

        assertTrue(action.perform(ctx));
        assertTrue(ctx.isBlacklisted("8.8.8.8", Instant.now()));

        assertEquals(0, ctx.getEvidenceCollector().findByIp(src).getExceptions());
    }
}

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;

import org.junit.Test;

import nl.ctrlaltdev.harbinger.rule.DetectionRuleLoader;


public class DefaultHarbingerContextTest {

    private DefaultHarbingerContext ctx = new DefaultHarbingerContext(new DetectionRuleLoader().load());

    @Test
    public void shouldHoldDependencies() {
        assertNotNull(ctx.getEvidenceCollector());
        assertNotNull(ctx.getResponseDecider());
    }

    @Test
    public void shouldValidate() {
        assertTrue(ctx.isValid(";--"));
        assertTrue(ctx.isValid("<SCRIPT>ALERT(1);</SCRIPT>"));
        assertTrue(ctx.isValid("<%53CRIPT>ALERT(1);</SCRIPT>"));
    }

    @Test
    public void shouldBlacklist() {
        ctx.blacklist("8.8.8.8", Instant.now().plusSeconds(1L));
        assertTrue(ctx.isBlacklisted("8.8.8.8", Instant.now()));
    }

    @Test
    public void shouldFilterForLog() {
        assertEquals("", DefaultHarbingerContext.filterForLog("\t\n\r"));
        assertEquals("test", DefaultHarbingerContext.filterForLog("test"));
    }

}

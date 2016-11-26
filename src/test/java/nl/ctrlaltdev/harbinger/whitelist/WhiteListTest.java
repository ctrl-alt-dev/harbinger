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
package nl.ctrlaltdev.harbinger.whitelist;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;

import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListBuilder;

public class WhiteListTest {

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private DetectionRule rule = new DetectionRule(new String[] { "", "MID", ".*" });

    @Test
    public void shouldWhiteListIP() {
        request.setRemoteAddr("8.8.8.8");
        assertTrue(new IpWhiteList("8.8.8.8").isWhitelisted(new Evidence(request)));
        assertFalse(new IpWhiteList("8.8.8.9").isWhitelisted(new Evidence(request)));
    }

    @Test
    public void shouldWhiteListParameter() {
        Evidence ev = new Evidence(new Evidence(request), rule, "param", "value");
        assertTrue(new ParameterWhiteList("param").isWhitelisted(ev));
        assertFalse(new ParameterWhiteList("zazam").isWhitelisted(ev));
    }

    @Test
    public void shouldWhiteListUrl() {
        request.setRequestURI("/some/where");
        Evidence ev = new Evidence(request);
        assertTrue(new UrlWhiteList("/some/where").isWhitelisted(ev));
        assertFalse(new UrlWhiteList("/no/where").isWhitelisted(ev));
    }

    @Test
    public void shouldWhiteListUser() {
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));
        assertTrue(new UserWhiteList("user").isWhitelisted(ev));
        assertFalse(new UserWhiteList("anonymous").isWhitelisted(ev));
    }

    @Test
    public void shouldWhitelistAnd() {
        request.setRemoteAddr("8.8.8.8");
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));
        assertTrue(WhiteListBuilder.create().and().ip("8.8.8.8").user("user").end().build().isWhitelisted(ev));
        assertFalse(WhiteListBuilder.create().and().ip("8.8.8.9").user("user").end().build().isWhitelisted(ev));
        assertFalse(WhiteListBuilder.create().and().ip("8.8.8.8").user("abuser").end().build().isWhitelisted(ev));
        assertFalse(WhiteListBuilder.create().and().ip("8.8.8.9").user("abuser").end().build().isWhitelisted(ev));
    }

    @Test
    public void shouldWhitelistOr() {
        request.setRemoteAddr("8.8.8.8");
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));
        assertTrue(WhiteListBuilder.create().or().ip("8.8.8.8").user("user").end().build().isWhitelisted(ev));
        assertTrue(WhiteListBuilder.create().or().ip("8.8.8.9").user("user").end().build().isWhitelisted(ev));
        assertTrue(WhiteListBuilder.create().or().ip("8.8.8.8").user("abuser").end().build().isWhitelisted(ev));
        assertFalse(WhiteListBuilder.create().or().ip("8.8.8.9").user("abuser").end().build().isWhitelisted(ev));
    }

}

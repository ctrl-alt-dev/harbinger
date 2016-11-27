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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;

import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListParser;

public class WhiteListParserTest {

    private WhiteListParser parser = new WhiteListParser();

    @Test
    public void shouldParseIp() {
        assertTrue(parser.parse("ip:127.0.0.1").isWhitelisted(new Evidence(new MockHttpServletRequest())));
        assertFalse(parser.parse("ip:10.0.0.1").isWhitelisted(new Evidence(new MockHttpServletRequest())));
    }

    @Test
    public void shouldParseParameter() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        DetectionRule rule = new DetectionRule(new String[] { "", "HIGH", "" });
        Evidence ev = new Evidence(new Evidence(request), rule, "name", "");

        assertTrue(parser.parse("parameter:name").isWhitelisted(ev));
        assertFalse(parser.parse("parameter:neem").isWhitelisted(ev));
    }

    @Test
    public void shouldParseUrl() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/pindakaas");
        Evidence ev = new Evidence(request);

        assertTrue(parser.parse("url:/pindakaas").isWhitelisted(ev));
        assertFalse(parser.parse("url:/wodkasju").isWhitelisted(ev));
    }

    @Test
    public void shouldParseUser() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));

        assertTrue(parser.parse("user:user").isWhitelisted(ev));
        assertFalse(parser.parse("user:nasi").isWhitelisted(ev));
    }

    @Test
    public void shouldParseAnd() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));

        assertTrue(parser.parse("and(user:user,ip:127.0.0.1)").isWhitelisted(ev));
        assertFalse(parser.parse("and(user:nasi,ip:127.0.0.1)").isWhitelisted(ev));
        assertFalse(parser.parse("and(user:user,ip:127.0.0.2)").isWhitelisted(ev));
        assertFalse(parser.parse("and(user:nasi,ip:127.0.0.2)").isWhitelisted(ev));
    }

    @Test
    public void shouldParseOr() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));

        assertTrue(parser.parse("or(user:user,ip:127.0.0.1)").isWhitelisted(ev));
        assertTrue(parser.parse("or(user:nasi,ip:127.0.0.1)").isWhitelisted(ev));
        assertTrue(parser.parse("or(user:user,ip:127.0.0.2)").isWhitelisted(ev));
        assertFalse(parser.parse("or(user:nasi,ip:127.0.0.2)").isWhitelisted(ev));
    }

    @Test
    public void shouldParseNested() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("user", ""));
        DetectionRule rule = new DetectionRule(new String[] { "", "HIGH", "" });
        ev = new Evidence(ev, rule, "test", "");

        assertTrue(parser.parse("and(or(user:user,ip:127.0.0.1),parameter:test)").isWhitelisted(ev));
        assertTrue(parser.parse("and(or(user:nasi,ip:127.0.0.1),parameter:test)").isWhitelisted(ev));
        assertTrue(parser.parse("and(or(user:user,ip:127.0.0.2),parameter:test)").isWhitelisted(ev));
        assertFalse(parser.parse("and(or(user:nasi,ip:127.0.0.2),parameter:test)").isWhitelisted(ev));
        assertFalse(parser.parse("and(or(user:user,ip:127.0.0.1),parameter:yest)").isWhitelisted(ev));
        assertFalse(parser.parse("and(or(user:nasi,ip:127.0.0.1),parameter:yest)").isWhitelisted(ev));
        assertFalse(parser.parse("and(or(user:user,ip:127.0.0.2),parameter:yest)").isWhitelisted(ev));
        assertFalse(parser.parse("and(or(user:nasi,ip:127.0.0.2),parameter:yest)").isWhitelisted(ev));
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailParsing() {
        parser.parse("and(or(and(or");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailParsingToo() {
        parser.parse("nasi:goreng");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailParsingThree() {
        parser.parse("eat(nasi:goreng)");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailParsingFour() {
        parser.parse("or()");
    }

    @Test
    public void shouldParseFromStream() throws IOException {
        parser.parse(new ByteArrayInputStream("and(ip:127.0.0.1)".getBytes()));
    }

    @Test
    public void shouldParseFromFile() throws IOException {
        WhiteList wl = parser.parse(new File("./src/test/resources/whitelist/test-whitelist.txt"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        Evidence ev = new Evidence(new Evidence(request), new TestingAuthenticationToken("admin", ""));

        assertTrue(wl.isWhitelisted(ev));

        DetectionRule rule = new DetectionRule(new String[] { "", "HIGH", "" });
        ev = new Evidence(new Evidence(request), rule, "test", "1");

        assertTrue(wl.isWhitelisted(ev));

        request.setRemoteAddr("127.0.0.2");
        assertTrue(wl.isWhitelisted(new Evidence(request)));
        request.setRemoteAddr("127.0.0.3");
        assertTrue(wl.isWhitelisted(new Evidence(request)));

        request.setRemoteAddr("127.0.0.4");
        assertFalse(wl.isWhitelisted(new Evidence(request)));
    }

}

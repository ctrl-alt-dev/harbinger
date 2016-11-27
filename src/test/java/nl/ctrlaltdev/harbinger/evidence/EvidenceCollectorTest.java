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

import static org.junit.Assert.assertEquals;

import java.time.Instant;
import java.util.Collections;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import nl.ctrlaltdev.harbinger.whitelist.builder.WhiteListBuilder;

public class EvidenceCollectorTest {

    private EvidenceCollector collector = new EvidenceCollector();
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    private Evidence evidence = new Evidence();

    @Before
    public void init() {
        request.setRemoteAddr("8.8.8.8");
        request.getSession(true);
        response.setStatus(200);
    }

    @Test
    public void shouldNotStoreUnattributed() {
        evidence = new Evidence(evidence, response);
        assertEquals(evidence, collector.store(evidence));
        assertEquals(evidence, collector.store(evidence));
        assertEquals(1, collector.findByIp(evidence).getNumberOfRequests());
    }

    @Test
    public void shouldStoreOnIP() {
        evidence = new Evidence(new Evidence(evidence, request), response);
        assertEquals(evidence, collector.store(evidence));
        assertEquals(evidence, collector.store(evidence));
        assertEquals(2, collector.findByIp(evidence).getNumberOfRequests());
    }

    @Test
    public void shouldStoreOnSession() {
        evidence = new Evidence(new Evidence(evidence, request), response);
        assertEquals(evidence, collector.store(evidence));
        assertEquals(evidence, collector.store(evidence));
        assertEquals(2, collector.findByIp(evidence).getNumberOfRequests());
    }

    @Test
    public void shouldEnhanceWithRequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        evidence = collector.enhanceAndStore(evidence);
        assertEquals("8.8.8.8", evidence.getIp());
    }

    @Test
    public void shouldEnhanceWithUser() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "user", Collections.singletonList(new SimpleGrantedAuthority("x"))));
        evidence = collector.enhanceAndStore(evidence);
        assertEquals("user", evidence.getUser());
    }

    @Test
    public void shouldClean() {
        evidence = new Evidence(new Evidence(evidence, request), response);
        collector.store(evidence);
        collector.store(evidence);
        collector.store(evidence);
        assertEquals(3, collector.findByIp(evidence).getNumberOfRequests());
        assertEquals(3, collector.findBySession(evidence).getNumberOfRequests());

        collector.clean(Instant.now().plusMillis(1)); // cleans anything before this time.

        assertEquals(1, collector.findByIp(evidence).getNumberOfRequests());
        assertEquals(1, collector.findBySession(evidence).getNumberOfRequests());
    }

    @Test
    public void shouldNotStoreWhiteListedEvidence() {
        collector = new EvidenceCollector(WhiteListBuilder.create().ip("8.8.8.8").build());

        evidence = new Evidence(new Evidence(evidence, request), response);
        evidence = collector.store(evidence);

        assertEquals(0, collector.findByIp(evidence).getNumberOfRequests());
    }

}

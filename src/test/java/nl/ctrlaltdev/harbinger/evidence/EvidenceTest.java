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

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.testutil.TestUtil;

public class EvidenceTest {

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();

    @Before
    public void init() {
        TestUtil.resetMockHttpSessionId();
    }

    @Test
    public void shouldBeUnknown() {
        assertEquals("Unknown ", new Evidence().toString());
    }

    @Test
    public void shouldBeWithRequestData() {
        request.setRemoteAddr("8.8.8.8");
        request.addHeader("X-Forwarded-For", "9.9.9.9");
        request.setRequestURI("/");
        request.getSession(true);
        assertEquals("IP 8.8.8.8 (9.9.9.9) with Session '1' on URL '/' ", new Evidence(request).toString());
    }

    @Test
    public void shouldBeWithResponseData() {
        request.setRemoteAddr("8.8.8.8");
        response.setStatus(500);
        assertEquals("IP 8.8.8.8 on URL '' triggered StatusCode 500", new Evidence(new Evidence(request), response).toString());
    }

    @Test
    public void shouldBeWithException() {
        request.setRemoteAddr("8.8.8.8");
        assertEquals("IP 8.8.8.8 on URL '' triggered Exception 'java.lang.Exception' ", new Evidence(new Evidence(request), new Exception()).toString());
    }

    @Test
    public void shouldBeWithRule() {
        DetectionRule rule = new DetectionRule(new String[] { "XSS", "MID", "xss" });
        request.setRemoteAddr("8.8.8.8");
        assertEquals("IP 8.8.8.8 on URL '' triggered Rule XSS with value 'str' ", new Evidence(new Evidence(request), rule, "str").toString());
    }

}

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
package nl.ctrlaltdev.harbinger.filter;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import mockit.Expectations;
import mockit.Mocked;
import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;
import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.response.RejectInputAction;
import nl.ctrlaltdev.harbinger.response.ResponseAction;
import nl.ctrlaltdev.harbinger.response.ResponseDecider;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.rule.DetectionRuleLoader;

public class HttpEvidenceFilterTest {

    private Set<DetectionRule> rules = new DetectionRuleLoader().load();
    private EvidenceCollector collector = new EvidenceCollector();
    private ResponseDecider decider = new ResponseDecider() {

        @Override
        public ResponseAction decide(Evidence evidence) {
            return new RejectInputAction();
        }
    };
    private HarbingerContext context = new DefaultHarbingerContext(rules, collector, decider);
    private HttpEvidenceFilter filter = new HttpEvidenceFilter(context);

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();

    @Mocked
    private FilterChain chain;

    @Test
    public void shouldCollectRequestResponse() throws IOException, ServletException {
        new Expectations() {{
                chain.doFilter(request, response);
        }};
        response.sendError(200);
        request.setRemoteAddr("8.8.8.8");
        filter.doFilter(request, response, chain);
        
        assertEquals(1, collector.findByIp(new Evidence(request)).getNumberOfRequests());
        assertEquals(1, collector.findByIp(new Evidence(request)).getHttp2xx());
        assertEquals(0, collector.findByIp(new Evidence(request)).getHttp5xx());
        assertEquals(0, collector.findByIp(new Evidence(request)).getExceptions());
    }

    @Test
    public void shouldCollectStatusCode500() throws IOException, ServletException {
        new Expectations() {{
                chain.doFilter(request, response);
        }};
        response.sendError(500);
        request.setRemoteAddr("8.8.8.8");
        filter.doFilter(request, response, chain);

        assertEquals(1, collector.findByIp(new Evidence(request)).getNumberOfRequests());
        assertEquals(0, collector.findByIp(new Evidence(request)).getHttp2xx());
        assertEquals(1, collector.findByIp(new Evidence(request)).getHttp5xx());
        assertEquals(0, collector.findByIp(new Evidence(request)).getExceptions());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldCollectException() throws IOException, ServletException {
        new Expectations() {{
                chain.doFilter(request, response);
                result = new IllegalArgumentException();
        }};
        request.setRemoteAddr("8.8.8.8");
        filter.doFilter(request, response, chain);

        assertEquals(1, collector.findByIp(new Evidence(request)).getNumberOfRequests());
        assertEquals(0, collector.findByIp(new Evidence(request)).getHttp2xx());
        assertEquals(0, collector.findByIp(new Evidence(request)).getHttp5xx());
        assertEquals(1, collector.findByIp(new Evidence(request)).getExceptions());
    }
    
    @Test
    public void shouldRejectBadParameters() throws IOException, ServletException {
        request.setRemoteAddr("8.8.8.8");
        request.addParameter("name", new String[] { "' or '1'='1" });

        filter.doFilter(request, response, chain);
    
        assertEquals(5, collector.findByIp(new Evidence(request)).getDetections());
        // The request is aborted, so there isn't a complete request.
        assertEquals(0, collector.findByIp(new Evidence(request)).getNumberOfRequests());
        assertEquals(0, collector.findByIp(new Evidence(request)).getExceptions());

        assertEquals(HttpServletResponse.SC_SERVICE_UNAVAILABLE, response.getStatus());
    }

    @Test
    public void shouldPassGoodParameters() throws IOException, ServletException {
        new Expectations() {{
                chain.doFilter(request, response);
            }};
        request.setRemoteAddr("8.8.8.8");
        request.addParameter("name", new String[] { "somewhere", "overtherainbow" });

        filter.doFilter(request, response, chain);

        assertEquals(0, collector.findByIp(new Evidence(request)).getDetections());
        assertEquals(1, collector.findByIp(new Evidence(request)).getNumberOfRequests());
        assertEquals(0, collector.findByIp(new Evidence(request)).getExceptions());
    }

}

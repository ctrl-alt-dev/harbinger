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
package nl.ctrlaltdev.harbinger.validator;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Set;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;
import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;
import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.response.RejectInputAction;
import nl.ctrlaltdev.harbinger.response.ResponseAction;
import nl.ctrlaltdev.harbinger.response.ResponseDecider;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;
import nl.ctrlaltdev.harbinger.rule.DetectionRuleLoader;

public class TripwiredValidatorTest {

    private Set<DetectionRule> rules = new DetectionRuleLoader().load();
    private EvidenceCollector collector = new EvidenceCollector();
    private ResponseDecider decider = new ResponseDecider() {

        @Override
        public ResponseAction decide(Evidence evidence) {
            return new RejectInputAction();
        }
    };
    private HarbingerContext context = new DefaultHarbingerContext(rules, collector, decider);
    private TripwiredValidator validator = new TripwiredValidator(context);

    @Test
    public void shouldInitialize() {
        validator.initialize(null);
    }

    @Test
    public void shouldFailOnXSS() {
        assertFalse(validator.isValid("bla bla <script>alert(1);</script>", null));
    }

    @Test
    public void shouldFailOnTagXSS() {
        assertFalse(validator.isValid(" onclick='alert(1);'", null));
    }

    @Test
    public void shouldFailOnStyleXSS() {
        assertFalse(validator.isValid(" style=\"background:url(javascript:alert(1))", null));
    }

    @Test
    public void shouldFailOnSQLi() {
        assertFalse(validator.isValid("' or '1'='1", null));
    }

    @Test
    public void shouldFailOnLFI() {
        assertFalse(validator.isValid("../../etc/passwd", null));
    }

    @Test
    public void shouldNotFailOnRegularInput() {
        assertTrue(validator.isValid("Boterham met pindakaas. Ik tover een Konijn. Uit de Hoge Hoed!", null));
    }

    @Test
    public void shouldFullReportWithSpring() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "user", Collections.singletonList(new SimpleGrantedAuthority("x"))));
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        request.setRemoteAddr("192.168.1.1");
        request.addHeader("X-Forwarded-For", "8.8.8.8");
        request.setSession(new MockHttpSession());

        assertFalse(validator.isValid("../../etc/passwd", null));
    }

    @Test
    public void shouldFullReportWithSpringWithLogInjection() {
        SecurityContextHolder.setContext(new SecurityContextImpl());
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "user", Collections.singletonList(new SimpleGrantedAuthority("x"))));
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        request.setRemoteAddr("192.168.1.1\n\r");
        request.addHeader("X-Forwarded-For", "\n\r\t8.8.8.8");
        request.setSession(new MockHttpSession());

        assertFalse(validator.isValid("../../etc/passwd\n\r\t", null));
    }

}

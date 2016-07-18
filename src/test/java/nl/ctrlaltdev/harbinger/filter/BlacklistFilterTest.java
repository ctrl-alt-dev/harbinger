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

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

import javax.servlet.ServletException;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import mockit.Expectations;
import mockit.Mocked;
import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;

public class BlacklistFilterTest {

    private DefaultHarbingerContext ctx = new DefaultHarbingerContext(Collections.emptySet());
    private BlacklistFilter filter = new BlacklistFilter(ctx);

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    @Mocked
    private MockFilterChain chain;

    @Test
    public void shouldPassThroughIfNotOnBlackList() throws IOException, ServletException {
        new Expectations() {{
            chain.doFilter(request, response);
        }};
        request.setRemoteAddr("8.8.8.8");
        filter.doFilter(request, response, chain);
    }

    @Test
    public void shouldRejectIfOnBlackList() throws IOException, ServletException {
        request.setRemoteAddr("8.8.8.8");
        ctx.blacklist("8.8.8.8", Instant.now().plusSeconds(1));
        filter.doFilter(request, response, chain);
    }

    @Test
    public void shouldUnblockBlackListAfterTimeout() throws IOException, ServletException, InterruptedException {
        new Expectations() {{
                chain.doFilter(request, response);
        }};
        request.setRemoteAddr("8.8.8.8");
        ctx.blacklist("8.8.8.8", Instant.now().plusSeconds(1));
        filter.doFilter(request, response, chain);
        Thread.sleep(1100L);
        filter.doFilter(request, response, chain);
    }

}

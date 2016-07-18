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
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;
import nl.ctrlaltdev.harbinger.HarbingerContext;

public class InvalidateSessionActionTest {

    private HarbingerContext ctx = new DefaultHarbingerContext(Collections.emptySet());
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    public void shouldInvalidateSession() {
        int id = Integer.parseInt(request.getSession(true).getId());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        assertTrue(new InvalidateSessionAction().perform(ctx));

        assertEquals(String.valueOf(id + 1), request.getSession(true).getId());
    }

    @Test
    public void shouldNotInvalidateSessionIfThereIsNone() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
        new InvalidateSessionAction().perform(ctx);
    }

    @Test
    public void shouldNotInvalidateSessionIfThereIsNoContext() {
        RequestContextHolder.setRequestAttributes(null);
        new InvalidateSessionAction().perform(ctx);
    }

}

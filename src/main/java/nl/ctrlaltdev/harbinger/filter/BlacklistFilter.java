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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.GenericFilterBean;

import nl.ctrlaltdev.harbinger.HarbingerContext;


/**
 * Blocks requests from blacklisted IPs.
 * Should be placed first in the spring security filter chain. 
 */
public class BlacklistFilter extends GenericFilterBean {

    private HarbingerContext ctx;

    @Autowired
    public BlacklistFilter(HarbingerContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!ctx.isBlacklisted(request.getRemoteAddr(), Instant.now())) {
            chain.doFilter(request, response);
        } else if (response instanceof HttpServletResponse) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

}

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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.GenericFilterBean;

import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;

/**
 * collects evidence for each Http Request.
 * Should be placed last the Spring Security Filter Chain.
 */
public class HttpEvidenceFilter extends GenericFilterBean {

    private HarbingerContext ctx;

    @Autowired
    public HttpEvidenceFilter(HarbingerContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Evidence evidence = new Evidence();
        if (request instanceof HttpServletRequest) {
            evidence = new Evidence(evidence, (HttpServletRequest) request);
        }
        try {
            chain.doFilter(request, response);
        } catch (IOException | ServletException | RuntimeException ex) {
            evidence = new Evidence(evidence, ex);
            throw ex;
        } finally {
            if (response instanceof HttpServletResponse) {
                Evidence ev = ctx.getEvidenceCollector().store(new Evidence(evidence, (HttpServletResponse) response));
                ctx.getResponseDecider().decide(ev).perform(ctx);
            }
        }
    }
}

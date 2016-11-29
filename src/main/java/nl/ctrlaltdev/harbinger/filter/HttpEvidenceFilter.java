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
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;

/**
 * Collects evidence for each HTTP Request. Should be placed last the Spring
 * Security Filter Chain.
 */
public class HttpEvidenceFilter extends OncePerRequestFilter {

    private HarbingerContext ctx;
    private boolean validateRequestParameters;

    /**
     * Creates a new HttpEvidenceFilter that validates all request parameters.
     * @param ctx the Harbinger Context.
     */
    public HttpEvidenceFilter(HarbingerContext ctx) {
        this(ctx, true);
    }

    /**
     * Creates a new HttpEvidenceFilter.
     * @param ctx the HarbingerContext.
     * @param validateRequestParameters if true, Harbinger checks all request
     *        parameters for malicious input.
     */
    public HttpEvidenceFilter(HarbingerContext ctx, boolean validateRequestParameters) {
        this.ctx = ctx;
        this.validateRequestParameters = validateRequestParameters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Evidence evidence = new Evidence(request);
        if (isValid(request, evidence)) {
            try {
                chain.doFilter(request, response);
            } catch (IOException | ServletException | RuntimeException ex) {
                evidence = new Evidence(evidence, ex);
                throw ex;
            } finally {
                Evidence ev = ctx.getEvidenceCollector().store(new Evidence(evidence, response));
                ctx.getResponseDecider().decide(ev).perform(ctx);
            }
        } else {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

    private boolean isValid(HttpServletRequest request, Evidence evidence) {
        if (validateRequestParameters) {
            for (Map.Entry<String, String[]> e : request.getParameterMap().entrySet()) {
                for (String v : e.getValue()) {
                    if (!ctx.isValidParameter(evidence, e.getKey(), v)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}

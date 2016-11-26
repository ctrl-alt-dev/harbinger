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

import java.time.Instant;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import nl.ctrlaltdev.harbinger.DefaultHarbingerContext;
import nl.ctrlaltdev.harbinger.rule.DetectionRule;

public class Evidence {

    final private Instant timestamp;
    private String ip;
    private String forwardedFor;
    private String user;
    private String session;
    private String input;
    private String url;
    private int statusCode;
    private DetectionRule rule;
    private String parameterName;
    private String value;
    private Class<? extends Exception> exceptionType;
    private String exceptionMessage;

    public Evidence() {
        this.timestamp = Instant.now();
    }

    protected Evidence(Evidence src) {
        this.timestamp = src.timestamp;
        this.ip = src.ip;
        this.forwardedFor = src.forwardedFor;
        this.user = src.user;
        this.session = src.session;
        this.input = src.input;
        this.url = src.url;
        this.statusCode = src.statusCode;
        this.rule = src.rule;
        this.parameterName = src.parameterName;
        this.value = src.value;
        this.exceptionMessage = src.exceptionMessage;
        this.exceptionType = src.exceptionType;
    }

    public Evidence(HttpServletRequest request) {
        this(new Evidence(), request);
    }

    public Evidence(Evidence src, HttpServletRequest req) {
        this(src);
        this.ip = req.getRemoteAddr();
        this.forwardedFor = req.getHeader("X-Forwarded-For");
        HttpSession session = req.getSession(false);
        this.session = session == null ? null : session.getId();
        this.url = req.getRequestURI();
    }

    public Evidence(Evidence src, HttpServletResponse resp) {
        this(src);
        this.statusCode = resp.getStatus();
    }

    public Evidence(Evidence src, Authentication auth) {
        this(src);
        Object principal = auth.getPrincipal();
        if (principal instanceof UserDetails) {
            user = ((UserDetails) principal).getUsername();
        } else {
            user = auth.getName();
        }
    }

    public Evidence(Evidence src, DetectionRule rule, String value) {
        this(src);
        this.rule = rule;
        this.value = value;
    }

    public Evidence(Evidence src, DetectionRule rule, String name, String value) {
        this(src);
        this.rule = rule;
        this.parameterName = name;
        this.value = value;
    }

    public Evidence(Evidence src, Exception ex) {
        this(src);
        this.exceptionType = ex.getClass();
        this.exceptionMessage = ex.getMessage();
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getForwardedFor() {
        return forwardedFor;
    }

    public String getIp() {
        return ip;
    }

    public String getUser() {
        return user;
    }

    public String getSession() {
        return session;
    }

    public String getInput() {
        return input;
    }

    public String getUrl() {
        return url;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public DetectionRule getRule() {
        return rule;
    }

    public String getParameterName() {
        return parameterName;
    }

    public String getValue() {
        return value;
    }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

    public Class<? extends Exception> getExceptionType() {
        return exceptionType;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (user != null) {
            sb.append("User '");
            sb.append(DefaultHarbingerContext.filterForLog(user));
            sb.append("' ");
        }
        if (ip != null) {
            if (sb.length() != 0) {
                sb.append("with ");
            }
            sb.append("IP ");
            sb.append(DefaultHarbingerContext.filterForLog(ip));
            sb.append(" ");
            if (forwardedFor != null) {
                sb.append("(");
                sb.append(DefaultHarbingerContext.filterForLog(forwardedFor));
                sb.append(") ");
            }
        }
        if (session != null) {
            sb.append("with Session '");
            sb.append(DefaultHarbingerContext.filterForLog(session));
            sb.append("' ");
        }
        if (url != null) {
            sb.append("on URL '");
            sb.append(DefaultHarbingerContext.filterForLog(url));
            sb.append("' ");
        }
        if (sb.length() == 0) {
            sb.append("Unknown ");
        }
        if (rule != null) {
            sb.append("triggered Rule ");
            sb.append(rule.getName());
            if (parameterName != null) {
                sb.append(" on parameter '");
                sb.append(parameterName);
                sb.append("'");
            }
            sb.append(" with value '");
            sb.append(DefaultHarbingerContext.filterForLog(value));
            sb.append("' ");
        }
        if (exceptionType != null) {
            sb.append("triggered Exception '");
            sb.append(DefaultHarbingerContext.filterForLog(exceptionType.getName()));
            sb.append("' ");
        }
        if (statusCode >= 400) {
            sb.append("triggered StatusCode ");
            sb.append(statusCode);
        }
        return sb.toString();
    }
}

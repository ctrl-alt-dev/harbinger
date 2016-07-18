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

import javax.servlet.http.HttpSession;

import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import nl.ctrlaltdev.harbinger.HarbingerContext;


/**
 * Invalidates the session if there is one. 
 */
public class InvalidateSessionAction implements ResponseAction {

    @Override
    public boolean perform(HarbingerContext ctx) {
        ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (sra != null) {
            HttpSession session = sra.getRequest().getSession(false);
            if (session != null) {
                LoggerFactory.getLogger(getClass()).warn("Invalidated session '{}'", session.getId());
                session.invalidate();
            }
        }
        return true;
    }

}

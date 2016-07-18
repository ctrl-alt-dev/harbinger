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
package nl.ctrlaltdev.harbinger;

import java.time.Instant;

import nl.ctrlaltdev.harbinger.evidence.EvidenceCollector;
import nl.ctrlaltdev.harbinger.response.ResponseDecider;

/**
 * Main entry point for the Harbinger API. 
 */
public interface HarbingerContext {

    /**
     * @return the evidenceCollector.
     */
    EvidenceCollector getEvidenceCollector();

    /**
     * @return the responseDecider.
     */
    ResponseDecider getResponseDecider();

    /**
     * allows Harbinger to react to user input using JSR-303 bean validation.
     * @param input the input to check against attack signatures.
     * @return true if the input should be blocked (determined by the ResponseDecider). 
     */
    boolean isValid(String input);

    /**
     * checks if the given remote address is blacklisted.
     * @param remoteAddr the remote IP address.
     * @param now the reference instant (addresses are temporarily blacklisted). 
     * @return true if the IP is blacklisted.
     */
    boolean isBlacklisted(String remoteAddr, Instant now);

    /**
     * blacklists the given remote address until the given instant. 
     * @param remoteAddr the remote address.
     * @param until the instant.
     */
    void blacklist(String remoteAddr, Instant until);

}

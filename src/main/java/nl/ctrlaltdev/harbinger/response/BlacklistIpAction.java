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

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import nl.ctrlaltdev.harbinger.HarbingerContext;
import nl.ctrlaltdev.harbinger.evidence.Evidence;
/**
 * Blacklists the IP from the evidence for the given amount of time. 
 */
public class BlacklistIpAction implements ResponseAction {

    private int minutes;
    private Evidence ev;

    public BlacklistIpAction(Evidence ev, int minutes) {
        this.ev = ev;
        this.minutes = minutes;
    }

    @Override
    public boolean perform(HarbingerContext ctx) {
        ctx.blacklist(ev.getIp(), Instant.now().plus(minutes, ChronoUnit.MINUTES));
        return true;
    }
}

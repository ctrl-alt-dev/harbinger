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
package nl.ctrlaltdev.harbinger.whitelist;

import java.util.List;

import nl.ctrlaltdev.harbinger.evidence.Evidence;

/**
 * White lists evidence if one of its composites white lists it.
 */
public class OrWhiteList implements WhiteList {

    private List<WhiteList> whitelist;

    public OrWhiteList(List<WhiteList> whitelist) {
        this.whitelist = whitelist;
    }

    @Override
    public boolean isWhitelisted(Evidence ev) {
        for (WhiteList w : whitelist) {
            if (w.isWhitelisted(ev)) {
                return true;
            }
        }
        return false;
    }

}

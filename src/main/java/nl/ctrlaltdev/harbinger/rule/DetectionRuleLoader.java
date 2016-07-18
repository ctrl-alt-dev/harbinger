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
package nl.ctrlaltdev.harbinger.rule;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class DetectionRuleLoader {

    private static final String DEFAULT_RULES = "/default-rules.txt";

    public Set<DetectionRule> load() {
        return load(DEFAULT_RULES);
    }

    public Set<DetectionRule> load(String resource) {
        try {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream(resource)))) {
                return load(in);
            } catch (IOException e) {
                throw new RuntimeException("Failed reading " + resource, e);
            }
        } catch (NullPointerException ex) {
            throw new RuntimeException("Failed opening " + resource + " from classpath.");
        }
    }

    public Set<DetectionRule> load(BufferedReader in) {
        Set<DetectionRule> results = new HashSet<>();
        in.lines().forEach((s) -> this.onLine(s, results));
        return results;
    }

    private void onLine(String line, Set<DetectionRule> detections) {
        if (!line.startsWith("#")) {
            String[] str = new String[3];
            int firstIndex = line.indexOf(',');
            int secondIndex = line.indexOf(',', firstIndex + 1);
            str[0] = line.substring(0, firstIndex);
            str[1] = line.substring(firstIndex + 1, secondIndex);
            str[2] = line.substring(secondIndex + 1);
            detections.add(new DetectionRule(str));
        }
    }

}

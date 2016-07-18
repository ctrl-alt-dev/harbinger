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

import java.util.regex.Pattern;

public class DetectionRule {

    public static enum Level {
        LOW(1), MID(5), HIGH(25);

        private int score;

        private Level(int score) {
            this.score = score;
        }

        public int getScore() {
            return score;
        }
    }

    private String name;
    private Level level;
    private Pattern pattern;

    public DetectionRule(String[] str) {
        if ((str == null) || (str.length != 3)) {
            throw new IllegalArgumentException("Invalid DetectionRule");
        }
        name = str[0];
        level = Level.valueOf(str[1]);
        pattern = Pattern.compile(str[2]);
    }

    public String getName() {
        return name;
    }

    public Level getLevel() {
        return level;
    }

    public Pattern getPattern() {
        return pattern;
    }

    public boolean matches(String value) {
        return pattern.matcher(value).find();
    }
}

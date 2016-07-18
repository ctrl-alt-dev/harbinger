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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import nl.ctrlaltdev.harbinger.rule.DetectionRule.Level;

public class DetectionRuleTest {

    @Test
    public void shouldConstruct() {
        DetectionRule rule = new DetectionRule(new String[] { "test", "LOW", "test" });
        assertEquals(Level.LOW, rule.getLevel());
        assertEquals("test", rule.getName());
        assertTrue(rule.matches("test"));
        assertFalse(rule.matches("rest"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotConstructBecauseNoArgs() {
        new DetectionRule(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotConstructBecauseIncorrectArgs() {
        new DetectionRule(new String[4]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotConstructBecauseBadEnum() {
        new DetectionRule(new String[] { "test", "XXX", "A" });
    }

}

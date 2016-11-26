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
package nl.ctrlaltdev.harbinger.whitelist.builder;

import java.util.ArrayList;
import java.util.List;

import nl.ctrlaltdev.harbinger.whitelist.AndWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.IpWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.OrWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.ParameterWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.UrlWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.UserWhiteList;
import nl.ctrlaltdev.harbinger.whitelist.WhiteList;

/**
 * Utiltity to programatically create white lists.
 */
public class WhiteListBuilder {

    private enum Mode {
        AND, OR;
    }

    public static WhiteList empty() {
        return new AndWhiteList();
    }

    public static WhiteListBuilder create() {
        return new WhiteListBuilder(null, Mode.OR);
    }

    private WhiteListBuilder parent;
    private List<WhiteList> rules = new ArrayList<>();
    private Mode mode;

    protected WhiteListBuilder(WhiteListBuilder parent, Mode mode) {
        this.parent = parent;
        this.mode = mode;
    }

    public WhiteListBuilder and() {
        return new WhiteListBuilder(this, Mode.AND);
    }

    public WhiteListBuilder or() {
        return new WhiteListBuilder(this, Mode.OR);
    }

    public WhiteListBuilder end() {
        return parent.end(this);
    }

    private WhiteListBuilder end(WhiteListBuilder child) {
        rules.add(child.buildInternal());
        return this;
    }

    public WhiteListBuilder ip(String ip) {
        rules.add(new IpWhiteList(ip));
        return this;
    }

    public WhiteListBuilder parameter(String parameter) {
        rules.add(new ParameterWhiteList(parameter));
        return this;
    }

    public WhiteListBuilder url(String url) {
        rules.add(new UrlWhiteList(url));
        return this;
    }

    public WhiteListBuilder user(String user) {
        rules.add(new UserWhiteList(user));
        return this;
    }

    protected WhiteList buildInternal() {
        switch (mode) {
        case AND:
            return new AndWhiteList(rules);
        case OR:
            return new OrWhiteList(rules);
        default:
            throw new IllegalStateException(String.valueOf(mode));
        }
    }

    public WhiteList build() {
        if (parent != null) {
            throw new IllegalStateException("Missing call to end()");
        }
        return buildInternal();
    }

}

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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

import nl.ctrlaltdev.harbinger.whitelist.WhiteList;

public class WhiteListParser {

    private static enum Keyword {
        AND, IP, OR, PARAMETER, URL, USER;
    }

    private static final String SYMBOLS = "(),:";

    public WhiteList parse(File in) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(in))){
            return parse(reader);
        }
    }

    public WhiteList parse(InputStream in) throws IOException {
        return parse(new BufferedReader(new InputStreamReader(in)));
    }

    public WhiteList parse(BufferedReader in) throws IOException {
        WhiteListBuilder builder = WhiteListBuilder.create();
        String line = in.readLine();
        int lineCnt = 1;
        while (line != null) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                try {
                    builder = parse(builder, line);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException("In line " + lineCnt, ex);
                }
            }
            lineCnt++;
            line = in.readLine();
        }
        return builder.build();
    }

    public WhiteList parse(String line) {
        WhiteListBuilder builder = parse(WhiteListBuilder.create(), line);
        return builder.build();
    }

    private WhiteListBuilder parse(WhiteListBuilder builder, String line) {
        List<String> tokens = splitIntoTokens(line);
        Keyword last = null;
        String symbol = null;
        for (String token : tokens) {
            if (last == null) {
                for (Keyword k : Keyword.values()) {
                    if (k.name().toLowerCase().equals(token)) {
                        last = k;
                        break;
                    }
                }
                if (last == null) {
                    throw new IllegalArgumentException("Missing keyword at '" + token + "'");
                }
            } else if (symbol == null) {
                if ((token.length() != 1)||(!SYMBOLS.contains(token))) {
                    throw new IllegalArgumentException("Expected symbol at '" + token + "'");
                } else {
                    symbol = token;
                }
                if (",".equals(symbol)) {
                    symbol = null;
                    last = null;
                } else if (")".equals(symbol)) {
                    builder = builder.end();
                    symbol = null;
                } else if ("(".equals(symbol)) {
                    switch (last) {
                    case AND:
                        builder = builder.and();
                        break;
                    case OR:
                        builder = builder.or();
                        break;
                    default:
                        throw new IllegalArgumentException("Expected compound statement.");
                    }
                    last = null;
                    symbol = null;
                }
            } else {
                builder = buildToken(builder, last, symbol, token);
                symbol = null;
            }
        }
        return builder;
    }

    private WhiteListBuilder buildToken(WhiteListBuilder builder, Keyword last, String symbol, String token) {
        if (":".equals(symbol)) {
            switch (last) {
            case IP:
                builder = builder.ip(token);
                break;
            case PARAMETER:
                builder = builder.parameter(token);
                break;
            case URL:
                builder = builder.url(token);
                break;
            case USER:
                builder = builder.user(token);
                break;
            default:
                throw new IllegalArgumentException("Expected single statement.");
            }
        } else {
            throw new IllegalArgumentException("Unexpected symbol " + symbol);
        }
        return builder;
    }

    private List<String> splitIntoTokens(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (int t = 0; t < line.length(); t++) {
            String token = "" + line.charAt(t);
            if (SYMBOLS.contains(token)) {
                if (sb.length()>0) {
                    tokens.add(urlDecode(sb.toString()));
                    sb.delete(0, sb.length());
                }
                tokens.add(token);
            } else {
                sb.append(line.charAt(t));
            }
        }
        if (sb.length() > 0) {
            tokens.add(sb.toString());
        }
        return tokens;
    }

    private String urlDecode(String str) {
        if (str.indexOf('%') >= 0) {
            try {
                return URLDecoder.decode(str, "UTF-8");
            } catch (UnsupportedEncodingException | IllegalArgumentException ex) {
                return str;
            }
        } else {
            return str;
        }
    }

}

/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.formatting;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * Checks that XML document is 'pretty-printed', including Base64 values.
 */
public class CustomBase64FormattingChecker implements FormattingChecker {
    private int lineLength;
    private String lineSeparatorRegex;

    /**
     * Creates new checker.
     * @param lineLength            Expected base64 maximum line length
     * @param lineSeparatorRegex    Regex matching line separator used in Base64 values
     */
    public CustomBase64FormattingChecker(int lineLength, String lineSeparatorRegex) {
        this.lineLength = lineLength;
        this.lineSeparatorRegex = lineSeparatorRegex;
    }

    @Override
    public void checkDocument(String document) {
        assertThat(document, containsString("\n"));
    }

    @Override
    public void checkBase64Value(String value) {
        String[] lines = value.split(lineSeparatorRegex);
        if (lines.length == 0) return;

        for (int i = 0; i < lines.length - 1; ++i) {
            assertThat(lines[i], matchesPattern(BASE64_PATTERN));
            assertEquals(lineLength, lines[i].length());
        }

        assertThat(lines[lines.length - 1], matchesPattern(BASE64_PATTERN));
        assertThat(lines[lines.length - 1].length(), lessThanOrEqualTo(lineLength));
    }

    @Override
    public void checkBase64ValueWithSpacing(String value) {
        /* spacing is added only if the value has multiple lines */
        if (value.length() <= lineLength) {
            assertThat(value, matchesRegex(BASE64_PATTERN));
            return;
        }

        assertThat(value.length(), greaterThanOrEqualTo(2));
        assertThat(value, startsWith("\n"));
        assertThat(value, endsWith("\n"));
        checkBase64Value(value.substring(1, value.length() - 1));
    }
}

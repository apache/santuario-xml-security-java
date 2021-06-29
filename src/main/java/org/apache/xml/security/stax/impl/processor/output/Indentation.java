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
package org.apache.xml.security.stax.impl.processor.output;

import javax.xml.stream.XMLStreamConstants;

import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

class Indentation {

    static final Indentation DEFAULT = new Indentation(null, null, 0);

    private final String lineSeparator;
    private final String increment;
    private final int offset;

    Indentation(String lineSeparator, String increment, int offset) {
        this.lineSeparator = lineSeparator;
        this.increment = increment;
        this.offset = offset;
    }

    String getLineSeparator() {
        return lineSeparator;
    }

    String getIncrement() {
        return increment;
    }

    int getOffset() {
        return offset;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (lineSeparator != null) {
            builder.append(lineSeparator);
        }
        if (increment != null) {
            builder.append(increment);
        }
        return builder.append(':').append(offset).toString();
    }

    static boolean isWhitespace(CharSequence characters) {
        return characters.codePoints().allMatch(codePoint -> Character.isWhitespace(codePoint));
    }

    static boolean isWhitespace(XMLSecEvent xmlSecEvent) {
        int eventType = xmlSecEvent.getEventType();
        if (eventType == XMLStreamConstants.CHARACTERS || eventType == XMLStreamConstants.SPACE) {
            return isWhitespace(xmlSecEvent.asCharacters().getData());
        }
        return false;
    }
}

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

import java.util.regex.Pattern;

/**
 * Checks document formatting where output depends on formatting options.
 * Base64 values can be treated in two ways: relatively long values can have additional line breaks
 * to separate them from element tags.
 */
public interface FormattingChecker {
    /**
     * This pattern checks if a string contains only characters from the Base64 alphabet, including padding.
     */
    Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]*$");

    /**
     * Checks the formatting of the whole document.
     * @param document  XML document as string
     *
     * @implSpec It is assumed that the document contains at least one nested element.
     */
    void checkDocument(String document);

    /**
     * Checks encoded base64 element/attribute value.
     * @param value Element value
     */
    void checkBase64Value(String value);

    /**
     * Checks encoded base64 element value with additional spacing.
     * @param value Element value
     */
    void checkBase64ValueWithSpacing(String value);
}

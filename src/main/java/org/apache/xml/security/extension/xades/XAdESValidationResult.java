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
package org.apache.xml.security.extension.xades;

import java.util.Collections;
import java.util.List;

/**
 * Result of XAdES-B-B validation performed by {@link XAdESBBValidator}.
 *
 * <p>A result can represent three distinct outcomes:
 * <ol>
 *   <li>{@link #isXAdESPresent()} == {@code false} — no XAdES qualifying properties were found;
 *       validation was not attempted.</li>
 *   <li>{@link #isXAdESPresent()} == {@code true} and {@link #isValid()} == {@code true} —
 *       XAdES-B-B properties are present and all checks passed.</li>
 *   <li>{@link #isXAdESPresent()} == {@code true} and {@link #isValid()} == {@code false} —
 *       XAdES-B-B properties are present but one or more checks failed;
 *       details are in {@link #getViolations()}.</li>
 * </ol>
 */
public final class XAdESValidationResult {

    private final boolean xadesPresent;
    private final List<String> violations;

    XAdESValidationResult(boolean xadesPresent, List<String> violations) {
        this.xadesPresent = xadesPresent;
        this.violations = Collections.unmodifiableList(violations);
    }

    /** Returns a result indicating no XAdES properties were found. */
    static XAdESValidationResult notPresent() {
        return new XAdESValidationResult(false, Collections.emptyList());
    }

    /**
     * Returns {@code true} if {@code xades132:QualifyingProperties} was found in
     * the signature's {@code ds:Object} elements.
     */
    public boolean isXAdESPresent() {
        return xadesPresent;
    }

    /**
     * Returns {@code true} if XAdES is present and all validation checks passed.
     * Returns {@code false} if XAdES is absent or if any check failed.
     */
    public boolean isValid() {
        return xadesPresent && violations.isEmpty();
    }

    /**
     * Returns an unmodifiable list of violation messages.
     * Empty when {@link #isValid()} is {@code true} or when XAdES is not present.
     */
    public List<String> getViolations() {
        return violations;
    }

    @Override
    public String toString() {
        if (!xadesPresent) {
            return "XAdESValidationResult[xadesPresent=false]";
        }
        return "XAdESValidationResult[valid=" + isValid() + ", violations=" + violations + "]";
    }
}

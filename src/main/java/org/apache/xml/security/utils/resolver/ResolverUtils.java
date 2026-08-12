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
package org.apache.xml.security.utils.resolver;

/**
 * Shared utility methods for resource resolver implementations.
 */
public final class ResolverUtils {

    private ResolverUtils() {
    }

    /**
     * Returns {@code true} if {@code uri} does not start with {@code file:}.
     * Returns {@code false} for {@code null}, empty strings, relative URIs (no {@code ':'}),
     * and {@code file:} URIs.
     *
     * @param uri the URI string to test; may be {@code null}
     * @return {@code true} if {@code uri} has a non-{@code file:} scheme
     */
    public static boolean hasExplicitNonFileScheme(String uri) {
        if (uri == null || uri.isEmpty()) {
            return false;
        }
        if (uri.indexOf(':') <= 0) {
            return false; // no scheme present — relative URI or fragment
        }
        return !uri.startsWith("file:");
    }
}

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
package org.apache.xml.security.stax.impl.resourceResolvers;

/**
 * Helper methods shared by the StAX resource resolvers.
 */
final class ResolverUtils {

    private ResolverUtils() {
        // utility class
    }

    /**
     * Returns the scheme for a URI.
     *
     * @param uri the URI
     * @return the scheme, or {@code null} if none
     */
    static String scheme(String uri) {
        if (uri == null) {
            return null;
        }
        char[] uriChars = uri.toCharArray();
        // Similar to java.net.URI::parse. Find ':' before any of '/', '?',
        // or '#', and treat the characters before it as scheme.
        for (int i = 0; i < uriChars.length; i++) {
            if (uriChars[i] == '/' || uriChars[i] == '?' || uriChars[i] == '#') {
                return null;
            }
            if (uriChars[i] == ':') {
                // No validation on the output since we only care if it's
                // empty or equal to specific values.
                return uri.substring(0, i);
            }
        }
        return null;
    }
}

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

/**
 * Namespace URIs, prefixes, and element tag constants for XAdES v1.3.2 and v1.4.1.
 *
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
 *      ETSI EN 319 132-1 (XAdES)</a>
 */
public final class XAdESConstants {

    private XAdESConstants() {
    }

    public static final String XADES_V132_NS = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String XADES_V141_NS = "http://uri.etsi.org/01903/v1.4.1#";

    public static final String XADES_V132_PREFIX = "xades132";
    public static final String XADES_V141_PREFIX = "xades141";

    /** Reference type URI identifying a reference that covers {@code ds:SignedProperties}. */
    public static final String REFERENCE_TYPE_SIGNEDPROPERTIES = "http://uri.etsi.org/01903#SignedProperties";

    public static final String TAG_QUALIFYING_PROPERTIES = "QualifyingProperties";
    public static final String TAG_SIGNATURE_POLICY_IMPLIED = "SignaturePolicyImplied";
}

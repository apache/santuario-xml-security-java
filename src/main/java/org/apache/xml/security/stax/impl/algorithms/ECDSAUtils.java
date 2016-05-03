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
package org.apache.xml.security.stax.impl.algorithms;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

@Deprecated
public final class ECDSAUtils {

    private ECDSAUtils() {
        // complete
    }

    /**
     * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
     * <p/>
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r,s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param asn1Bytes
     * @return the decode bytes
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertASN1toXMLDSIG(byte asn1Bytes[]) throws IOException {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.convertASN1toXMLDSIG(asn1Bytes);
    }

    /**
     * Converts a XML Signature ECDSA Value to an ASN.1 DSA value.
     * <p/>
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r,s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param xmldsigBytes
     * @return the encoded ASN.1 bytes
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertXMLDSIGtoASN1(byte xmldsigBytes[]) throws IOException {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.convertXMLDSIGtoASN1(xmldsigBytes);
    }

    public static String getOIDFromPublicKey(ECPublicKey ecPublicKey) {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.getOIDFromPublicKey(ecPublicKey);
    }

    public static ECCurveDefinition getECCurveDefinition(String oid) {
        org.apache.xml.security.algorithms.implementations.ECDSAUtils.ECCurveDefinition curveDef = 
            org.apache.xml.security.algorithms.implementations.ECDSAUtils.getECCurveDefinition(oid);
        if (curveDef != null) {
            return new ECCurveDefinition(curveDef.getName(), curveDef.getOid(), curveDef.getField(), curveDef.getA(),
                                         curveDef.getB(), curveDef.getX(), curveDef.getY(), curveDef.getN(),
                                         curveDef.getH());
        }
        return null;
    }

    public static class ECCurveDefinition 
        extends org.apache.xml.security.algorithms.implementations.ECDSAUtils.ECCurveDefinition {
        
        public ECCurveDefinition(String name, String oid, String field, String a, String b, String x, String y, String n, int h) {
            super(name, oid, field, a, b, x, y, n, h);
        }
    }

    public static byte[] encodePoint(ECPoint ecPoint, EllipticCurve ellipticCurve) {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.encodePoint(ecPoint, ellipticCurve);
    }

    public static ECPoint decodePoint(byte[] encodedBytes, EllipticCurve ellipticCurve) {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.decodePoint(encodedBytes, ellipticCurve);
    }

    public static byte[] stripLeadingZeros(byte[] bytes) {
        return org.apache.xml.security.algorithms.implementations.ECDSAUtils.stripLeadingZeros(bytes);
    }
}

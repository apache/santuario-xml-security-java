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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.xml.security.test.javax.xml.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.Key;
import java.security.KeyException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;


/**
 * This is a class which supplies several KeySelector implementations
 *
 */
public class KeySelectors {

    /**
     * KeySelector which would always return the secret key specified in its
     * constructor.
     */
    public static class SecretKeySelector extends KeySelector {
        private final SecretKey key;
        public SecretKeySelector(byte[] bytes) {
            key = wrapBytes(bytes);
        }
        public SecretKeySelector(SecretKey key) {
            this.key = key;
        }

        @Override
        public KeySelectorResult select(KeyInfo ki,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            return new SimpleKSResult(key);
        }

        private SecretKey wrapBytes(final byte[] bytes) {
            return new SecretKey() {
                private static final long serialVersionUID = 3457835482691931082L;

                    @Override
                    public String getFormat() {
                        return "RAW";
                    }

                    @Override
                    public String getAlgorithm() {
                        return "Secret key";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return bytes.clone();
                    }
                };
        }
    }

    /**
     * KeySelector which would retrieve the X509Certificate out of the
     * KeyInfo element and return the public key.
     * NOTE: If there is an X509CRL in the KeyInfo element, then revoked
     * certificate will be ignored.
     */
    public static class RawX509KeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            for (XMLStructure kiType : keyInfo.getContent()) {
                if (kiType instanceof X509Data) {
                    X509Data xd = (X509Data) kiType;
                    Object[] entries = xd.getContent().toArray();
                    X509CRL crl = null;
                    // Looking for CRL before finding certificates
                    for (int i = 0; i < entries.length && crl == null; i++) {
                        if (entries[i] instanceof X509CRL) {
                            crl = (X509CRL) entries[i];
                        }
                    }
                    for (Object o : xd.getContent()) {
                        // skip non-X509Certificate entries
                        if (o instanceof X509Certificate) {
                            if (purpose != KeySelector.Purpose.VERIFY &&
                                crl != null &&
                                crl.isRevoked((X509Certificate)o)) {
                                continue;
                            } else {
                                return new SimpleKSResult(((X509Certificate) o).getPublicKey());
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate found!");
        }
    }

    /**
     * KeySelector which would retrieve the public key out of the
     * KeyValue element and return it.
     * NOTE: If the key algorithm doesn't match signature algorithm,
     * then the public key will be ignored.
     */
    public static class KeyValueKeySelector extends KeySelector {
        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            List<XMLStructure> list = keyInfo.getContent();
            for (XMLStructure xmlStructure : list) {
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue)xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    return new SimpleKSResult(pk);
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }
    }

    /**
     * KeySelector which would perform special lookup as documented
     * by the ie/baltimore/merlin-examples testcases and return the
     * matching public key.
     */
    public static class CollectionKeySelector extends KeySelector {
        private final CertificateFactory certFac;
        private final File certDir;
        private final List<X509Certificate> certs = new ArrayList<>();
        private static final int MATCH_SUBJECT = 0;
        private static final int MATCH_ISSUER = 1;
        private static final int MATCH_SERIAL = 2;
        private static final int MATCH_SUBJECT_KEY_ID = 3;
        private static final int MATCH_CERTIFICATE = 4;

        public CollectionKeySelector(File dir) throws CertificateException {
            certDir = dir;
            certFac = CertificateFactory.getInstance("X509");
            File[] files = new File(certDir, "certs").listFiles();
            if (files != null) {
                for (File file : files) {
                    try (FileInputStream fis = new FileInputStream(file)) {
                        X509Certificate cert = (X509Certificate) certFac.generateCertificate(fis);
                        if (cert != null) {
                            certs.add(cert);
                        }
                    } catch (Exception ex) {
                        // ignore non-cert files
                    }
                }
            }
        }

        public List<X509Certificate> match(
            int matchType, Object value, List<X509Certificate> pool
        ) {
            List<X509Certificate> matchResult = new ArrayList<>();

            for (X509Certificate c : pool) {

                switch (matchType) {
                case MATCH_SUBJECT:
                    Principal p1 = new javax.security.auth.x500.X500Principal((String)value);
                    if (c.getSubjectX500Principal().equals(p1)) {
                        matchResult.add(c);
                    }
                    break;
                case MATCH_ISSUER:
                    Principal p2 = new javax.security.auth.x500.X500Principal((String)value);
                    if (c.getIssuerX500Principal().equals(p2)) {
                        matchResult.add(c);
                    }
                    break;
                case MATCH_SERIAL:
                    if (c.getSerialNumber().equals(value)) {
                        matchResult.add(c);
                    }

                    break;
                case MATCH_SUBJECT_KEY_ID:
                    byte[] extension = c.getExtensionValue("2.5.29.14");
                    if (extension != null) {
                        byte[] extVal = new byte[extension.length - 4];
                        System.arraycopy(extension, 4, extVal, 0, extVal.length);

                        if (Arrays.equals(extVal, (byte[]) value)) {
                            matchResult.add(c);
                        }
                    }
                    break;
                case MATCH_CERTIFICATE:
                    if (c.equals(value)) {
                        matchResult.add(c);
                    }
                    break;
                }
            }
            return matchResult;
        }

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                                        KeySelector.Purpose purpose,
                                        AlgorithmMethod method,
                                        XMLCryptoContext context)
            throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            for (XMLStructure xmlStructure : keyInfo.getContent()) {
                try {
                    if (xmlStructure instanceof KeyName) {
                        String name = ((KeyName)xmlStructure).getName();
                        PublicKey pk = null;
                        try {
                            // Lookup the public key using the key name 'Xxx',
                            // i.e. the public key is in "certs/xxx.crt".
                            File certFile = new File(new File(certDir, "certs"),
                                name.toLowerCase()+".crt");
                            X509Certificate cert = (X509Certificate)
                                certFac.generateCertificate
                                (new FileInputStream(certFile));
                            pk = cert.getPublicKey();
                        } catch (FileNotFoundException e) {
                            // assume KeyName contains subject DN and search
                            // collection of certs for match
                            List<X509Certificate> result = match(MATCH_SUBJECT, name, certs);
                            int numOfMatches = result == null ? 0 : result.size();
                            if (numOfMatches != 1) {
                                throw new KeySelectorException
                                    ((numOfMatches == 0 ? "No":"More than one") +
                                     " match found");
                            }
                            pk = result.get(0).getPublicKey();
                        }
                        return new SimpleKSResult(pk);
                    } else if (xmlStructure instanceof RetrievalMethod) {
                        // Lookup the public key using the retrieval method.
                        // NOTE: only X509Certificate type is supported.
                        RetrievalMethod rm = (RetrievalMethod) xmlStructure;
                        String type = rm.getType();
                        if (type.equals(X509Data.RAW_X509_CERTIFICATE_TYPE)) {
                            String uri = rm.getURI();
                            X509Certificate cert = (X509Certificate)
                                certFac.generateCertificate
                                (new FileInputStream(new File(certDir, uri)));
                            return new SimpleKSResult(cert.getPublicKey());
                        } else {
                            throw new KeySelectorException
                                ("Unsupported RetrievalMethod type");
                        }
                    } else if (xmlStructure instanceof X509Data) {
                        List<?> content = ((X509Data)xmlStructure).getContent();
                        int size = content.size();
                        List<X509Certificate> result = null;
                        // Lookup the public key using the information
                        // specified in X509Data element, i.e. searching
                        // over the collection of certificate files under
                        // "certs" subdirectory and return those match.
                        for (int k = 0; k < size; k++) {
                            Object obj = content.get(k);
                            if (obj instanceof String) {
                                result = match(MATCH_SUBJECT, obj, certs);
                            } else if (obj instanceof byte[]) {
                                result = match(MATCH_SUBJECT_KEY_ID, obj, certs);
                            } else if (obj instanceof X509Certificate) {
                                result = match(MATCH_CERTIFICATE, obj, certs);
                            } else if (obj instanceof X509IssuerSerial) {
                                X509IssuerSerial is = (X509IssuerSerial) obj;
                                result = match(MATCH_SERIAL,
                                               is.getSerialNumber(), certs);
                                result = match(MATCH_ISSUER,
                                               is.getIssuerName(), result);
                            } else {
                                throw new KeySelectorException("Unsupported X509Data: " + obj);
                            }
                        }
                        int numOfMatches = result == null ? 0 : result.size();
                        if (numOfMatches != 1) {
                            throw new KeySelectorException
                                ((numOfMatches == 0 ? "No" : "More than one") +
                                 " match found");

                        }
                        return new SimpleKSResult(result.get(0).getPublicKey());
                    }
                } catch (Exception ex) {
                    throw new KeySelectorException(ex);
                }
            }
            throw new KeySelectorException("No matching key found!");
        }
    }

    public static class ByteUtil {

        private static String mapping = "0123456789ABCDEF";
        private static int numBytesPerRow = 6;

        private static String getHex(byte value) {
            int low = value & 0x0f;
            int high = (value >> 4) & 0x0f;
            char[] res = new char[2];
            res[0] = mapping.charAt(high);
            res[1] = mapping.charAt(low);
            return new String(res);
        }

        public static String dumpArray(byte[] in) {
            int numDumped = 0;
            StringBuilder buf = new StringBuilder(512);
            buf.append('{');
            for (int i = 0;i < (in.length / numBytesPerRow); i++) {
                for (int j=0; j < (numBytesPerRow); j++) {
                    buf.append("(byte)0x");
                    buf.append(getHex(in[i * numBytesPerRow+j]));
                    buf.append(", ");
                }
                numDumped += numBytesPerRow;
            }
            while (numDumped < in.length) {
                buf.append("(byte)0x");
                buf.append(getHex(in[numDumped]));
                buf.append(' ');
                numDumped += 1;
            }
            buf.append('}');
            return buf.toString();
        }
    }

    private static class SimpleKSResult implements KeySelectorResult {
        private final Key key;

        SimpleKSResult(Key key) { this.key = key; }

        @Override
        public Key getKey() { return key; }
    }
}

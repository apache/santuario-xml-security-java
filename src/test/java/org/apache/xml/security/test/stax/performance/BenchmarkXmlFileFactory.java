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

package org.apache.xml.security.test.stax.performance;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

public class BenchmarkXmlFileFactory {

    private static final Logger LOG = System.getLogger(BenchmarkXmlFileFactory.class.getName());

    public static final File DIR_TMP = resolveFile("target/performanceIT");
    public static final File FILE_SYMMETRIC_KEY = new File(DIR_TMP, "symkey.pcks12");
    public static final File FILE_INPUT_XML = new File(DIR_TMP, "input.xml");

    private static final String KS_PASSWORD = "default";
    private static final String ALIAS_ENCRYPTION_SYM_KEY = "encryptionSymKey";

    private final SecretKey encryptionSymKey;

    private final XMLInputFactory xmlInputFactory;
    private final Key key;
    private final X509Certificate cert;

    private final OutboundXMLSec outboundSignatureXMLSec;
    private final InboundXMLSec inboundSignatureXMLSec;
    private final OutboundXMLSec outboundEncryptionXMLSec;
    private final InboundXMLSec inboundDecryptionXMLSec;

    public BenchmarkXmlFileFactory(File symKeyStoreFile) {
        org.apache.xml.security.Init.init();
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        try {
            KeyStore symKeyStore = KeyStore.getInstance("PKCS12");
            try (InputStream inputStream = Files.newInputStream(symKeyStoreFile.toPath())) {
                symKeyStore.load(inputStream, KS_PASSWORD.toCharArray());
            }
            encryptionSymKey = (SecretKey) symKeyStore.getKey(ALIAS_ENCRYPTION_SYM_KEY, KS_PASSWORD.toCharArray());

            KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
            key = keyStore.getKey("transmitter", XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD.toCharArray());
            cert = (X509Certificate) keyStore.getCertificate("transmitter");
            // sign and verify stream
            outboundSignatureXMLSec = createOutboundSignatureXMLSec(key, cert);
            inboundSignatureXMLSec = createInboundSignatureXMLSec(cert);
            // encrypt and decrypt stream
            outboundEncryptionXMLSec = createOutboundEncryptionXMLSec(this.encryptionSymKey);
            inboundDecryptionXMLSec = createInboundEncryptionXMLSec(this.encryptionSymKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public void signAsStream(File input, File output) throws Exception {
        LOG.log(Level.DEBUG, "signAsStream(file={0}, output={1})", input, output);
        try (OutputStream outputStream = Files.newOutputStream(output.toPath())) {
            XMLStreamWriter xmlStreamWriter = outboundSignatureXMLSec.processOutMessage(outputStream, UTF_8.name());
            try (InputStream inputStream = Files.newInputStream(input.toPath())) {
                XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(inputStream);
                try {
                    XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                } finally {
                    xmlStreamReader.close();
                }
            } finally {
                xmlStreamWriter.close();
            }
        }
    }

    public void readSignedAsStream(File signedFile) throws Exception {
        LOG.log(Level.DEBUG, "readSignedAsStream(signedFile={0})", signedFile);
        try (InputStream inputStream = Files.newInputStream(signedFile.toPath())) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(inputStream);
            try {
                XMLStreamReader securityStreamReader = inboundSignatureXMLSec.processInMessage(xmlStreamReader);
                try {
                    while (securityStreamReader.hasNext()) {
                        securityStreamReader.next();
                    }
                } finally {
                    securityStreamReader.close();
                }
            } finally {
                xmlStreamReader.close();
            }
        }
    }

    public void signAsDOM(File file, File signedOutput) throws Exception {
        LOG.log(Level.DEBUG, "signAsDOM(file={0}, signedOutput={1})", file, signedOutput);
        Document document = XMLUtils.read(file, false);
        XMLSignature sig = new XMLSignature(document, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        Element root = document.getDocumentElement();
        root.insertBefore(sig.getElement(), root.getFirstChild());

        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        sig.addDocument("", transforms, "http://www.w3.org/2000/09/xmldsig#sha1");
        sig.sign(key);
        sig.addKeyInfo(cert);

        XMLUtils.outputDOM(document, signedOutput);
    }

    public void readSignedAsDOM(File signedFile) throws Exception {
        LOG.log(Level.DEBUG, "readSignedAsDOM(signedFile={0})", signedFile);
        Document document = XMLUtils.read(signedFile, false);
        Element signatureElement = (Element) document
            .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        XMLSignature xmlSignature = new XMLSignature(signatureElement, "", true);
        xmlSignature.checkSignatureValue(cert);
    }

    public void encryptAsStream(File inputFile, File outputFile) throws Exception {
        try (OutputStream outputStream = new FileOutputStream(outputFile)) {
            XMLStreamWriter xmlStreamWriter = outboundEncryptionXMLSec.processOutMessage(outputStream, UTF_8.name());
            try (InputStream inputStream = new FileInputStream(inputFile)) {
                XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(inputStream, UTF_8.name());
                try {
                    XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                } finally {
                    xmlStreamReader.close();
                }
            } finally {
                xmlStreamWriter.close();
            }
        }
    }

    public void decryptAsStream(File file) throws Exception {
        try (InputStream inputStream = new FileInputStream(file)) {
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(inputStream, UTF_8.name());
            try {
                XMLStreamReader securityStreamReader = inboundDecryptionXMLSec.processInMessage(xmlStreamReader);
                try {
                    while (securityStreamReader.hasNext()) {
                        securityStreamReader.next();
                    }
                } finally {
                    securityStreamReader.close();
                }
            } finally {
                xmlStreamReader.close();
            }
        }
    }

    public void encryptAsDOM(File inputFile, File outputFile) throws Exception {
        Document document = XMLUtils.read(inputFile, false);
        XMLCipher cipher = XMLCipher.getInstance("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        cipher.init(XMLCipher.ENCRYPT_MODE, encryptionSymKey);
        document = cipher.doFinal(document, document.getDocumentElement());
        XMLUtils.outputDOM(document, outputFile);
    }


    public Document decryptAsDOM(File file) throws Exception {
        Document document = XMLUtils.read(file, false);
        XMLCipher cipher = XMLCipher.getInstance("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
        cipher.init(XMLCipher.DECRYPT_MODE, encryptionSymKey);
        return cipher.doFinal(document, document.getDocumentElement());
    }

    // Important: this method is invoked by different JVM than the constructor.
    // That is why results are not shared via fields - it is not possible.
    // However we still use the same file system.
    public static void initFiles() throws Exception {
        DIR_TMP.mkdirs();

        // huge xml, nearly 29 MB
        generateLargeXMLFile(FILE_INPUT_XML, 50_000);

        final KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        final SecretKey encryptionSymKey = keygen.generateKey();
        final SecretKeyEntry entry = new SecretKeyEntry(encryptionSymKey);
        final KeyStore symKeyStore = KeyStore.getInstance("PKCS12");
        symKeyStore.load(null);
        symKeyStore.setEntry(ALIAS_ENCRYPTION_SYM_KEY, entry, new PasswordProtection(KS_PASSWORD.toCharArray()));
        try (OutputStream stream = Files.newOutputStream(FILE_SYMMETRIC_KEY.toPath())) {
            symKeyStore.store(stream, KS_PASSWORD.toCharArray());
        }
    }


    private static void generateLargeXMLFile(File target, int factor) throws Exception {
        LOG.log(Level.DEBUG, "generateLargeXMLFile(target={0}, factor={1})", target, factor);
        try (FileWriter fileWriter = new FileWriter(target, UTF_8, false)) {
            fileWriter.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            fileWriter.write("<test xmlns=\"http://www.example.com\">");
        }
        try (FileOutputStream fileOutputStream = new FileOutputStream(target, true)) {
            for (int i = 0; i < factor; i++) {
                int read = 0;
                byte[] buffer = new byte[4096];
                try (InputStream inputStream = BenchmarkXmlFileFactory.class.getClassLoader()
                    .getResourceAsStream("org/w3c/www/interop/xmlenc-core-11/plaintext.xml")) {
                    while ((read = inputStream.read(buffer)) != -1) {
                        fileOutputStream.write(buffer, 0, read);
                    }
                }
            }
            try (FileWriter fileWriter = new FileWriter(target, UTF_8, true)) {
                fileWriter.write("</test>");
            }
        }
    }


    private static OutboundXMLSec createOutboundSignatureXMLSec(final Key key, final X509Certificate cert)
        throws XMLSecurityException {
        XMLSecurityProperties xmlSecurityProperties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        xmlSecurityProperties.setActions(actions);
        xmlSecurityProperties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        xmlSecurityProperties.setSignatureKey(key);
        xmlSecurityProperties.setSignatureCerts(new X509Certificate[]{cert});
        xmlSecurityProperties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

        SecurePart securePart = new SecurePart(
                new QName("http://www.example.com", "test"),
                SecurePart.Modifier.Element,
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1"
        );
        xmlSecurityProperties.addSignaturePart(securePart);

        return XMLSec.getOutboundXMLSec(xmlSecurityProperties);
    }

    private static InboundXMLSec createInboundSignatureXMLSec(final X509Certificate cert) throws XMLSecurityException {
        XMLSecurityProperties inboundProperties = new XMLSecurityProperties();
        inboundProperties.setSignatureVerificationKey(cert.getPublicKey());
        return XMLSec.getInboundWSSec(inboundProperties);
    }

    private static OutboundXMLSec createOutboundEncryptionXMLSec(SecretKey encryptionSymKey) throws XMLSecurityException {
        XMLSecurityProperties xmlSecurityProperties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        xmlSecurityProperties.setActions(actions);
        xmlSecurityProperties.setEncryptionKey(encryptionSymKey);
        xmlSecurityProperties.setEncryptionSymAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");

        SecurePart securePart = new SecurePart(
                new QName("http://www.example.com", "test"),
                SecurePart.Modifier.Element
        );
        xmlSecurityProperties.addEncryptionPart(securePart);
        return XMLSec.getOutboundXMLSec(xmlSecurityProperties);
    }

    private static InboundXMLSec createInboundEncryptionXMLSec(SecretKey encryptionSymKey) throws XMLSecurityException {
        XMLSecurityProperties inboundProperties = new XMLSecurityProperties();
        inboundProperties.setDecryptionKey(encryptionSymKey);
        return XMLSec.getInboundWSSec(inboundProperties);
    }
}

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
package org.apache.xml.security.test.dom.transforms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.c14n.implementations.Canonicalizer20010315Excl;
import org.apache.xml.security.c14n.implementations.Canonicalizer20010315ExclOmitComments;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_Excl;
import org.apache.xml.security.stax.impl.transformer.canonicalizer.Canonicalizer20010315_ExclOmitCommentsTransformer;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

class EmptyNamespaceTest {

    private static final String message = "<SOAP-ENV:Body xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"XWSSGID-1465203363337-2063525437\">\n" +
            "\t<ec:SubmitRetrieveInterchangeAgreementsRequestResponse xmlns:ec=\"ec:services:wsdl:RetrieveInterchangeAgreementsRequest-2\" xmlns:ec1=\"ec:schema:xsd:CommonBasicComponents-0.1\">\n" +
            "\t\t<ns0:RetrieveInterchangeAgreementsResponse xmlns:ns0=\"ec:services:wsdl:RetrieveInterchangeAgreementsRequest-2\" xmlns:ns1=\"urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2\" xmlns:ns11=\"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2\" xmlns:ns2=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\" xmlns:ns4=\"ec:schema:xsd:CommonBasicComponents-1\" xmlns:ns9=\"ec:schema:xsd:CommonAggregateComponents-2\">\n" +
            "\t\t\t<ns9:InterchangeAgreement>\n" +
            "\t\t\t\t<ns11:SenderParty>\n" +
            "\t\t\t\t\t<ns2:EndpointID schemeID=\"GLN\">DEV1_NOTENC_WEB_PARTY</ns2:EndpointID>\n" +
            "\t\t\t\t\t<ns11:PartyIdentification>\n" +
            "\t\t\t\t\t\t<ns2:ID schemeID=\"GLN\">DEV1_NOTENC_WEB_PARTY</ns2:ID>\n" +
            "\t\t\t\t\t</ns11:PartyIdentification>\n" +
            "\t\t\t\t</ns11:SenderParty>\n" +
            "\t\t\t\t<ns11:ReceiverParty>\n" +
            "\t\t\t\t\t<ns2:EndpointID schemeID=\"GLN\">DEV1_NOTENC_APP_PARTY</ns2:EndpointID>\n" +
            "\t\t\t\t\t<ns11:PartyIdentification>\n" +
            "\t\t\t\t\t\t<ns2:ID schemeID=\"GLN\">DEV1_NOTENC_APP_PARTY</ns2:ID>\n" +
            "\t\t\t\t\t</ns11:PartyIdentification>\n" +
            "\t\t\t\t</ns11:ReceiverParty>\n" +
            "\t\t\t\t<ns9:SecurityInformation>\n" +
            "\t\t\t\t\t<ns4:ConfidentialityLevelCode>0</ns4:ConfidentialityLevelCode>\n" +
            "\t\t\t\t\t<ns4:IntegrityLevelCode>0</ns4:IntegrityLevelCode>\n" +
            "\t\t\t\t\t<ns4:AvailabilityLevelCode>0</ns4:AvailabilityLevelCode>\n" +
            "\t\t\t\t</ns9:SecurityInformation>\n" +
            "\t\t\t\t<ns2:DocumentTypeCode></ns2:DocumentTypeCode>\n" +
            "\t\t\t\t<ns2:ProfileID>Bundle</ns2:ProfileID>\n" +
            "\t\t\t</ns9:InterchangeAgreement>\n" +
            "\t\t</ns0:RetrieveInterchangeAgreementsResponse>\n" +
            "\t</ec:SubmitRetrieveInterchangeAgreementsRequestResponse>\n" +
            "</SOAP-ENV:Body>";

    @Test
    void doStAXTest() throws Exception {
        org.apache.xml.security.Init.init();
        org.apache.xml.security.stax.config.Init.init(null, EmptyNamespaceTest.class);

        List<String> inclusiveNamespaces = Arrays.asList("SOAP-ENV ec ec1 ns0 ns1 ns11 ns2 ns4 ns9".split(" "));
        Canonicalizer20010315_Excl transformer = new Canonicalizer20010315_ExclOmitCommentsTransformer();
        Map<String, Object> properties = new HashMap<>();
        properties.put(Canonicalizer20010315_Excl.INCLUSIVE_NAMESPACES_PREFIX_LIST, inclusiveNamespaces);

        transformer.setProperties(properties);

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            InputStream stream = new ByteArrayInputStream(message.getBytes(UTF_8))) {
            transformer.setOutputStream(outputStream);

            transformer.transform(stream);
            transformer.doFinal();

            String result = outputStream.toString();
            assertEquals(message, result);
        }
    }

    @Test
    void doDOMTest() throws Exception {
        org.apache.xml.security.Init.init();
        org.apache.xml.security.stax.config.Init.init(null, EmptyNamespaceTest.class);

        Canonicalizer20010315Excl transformer = new Canonicalizer20010315ExclOmitComments();

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(message.getBytes(UTF_8))) {
            document = XMLUtils.read(is, false);
        }

        String inclusiveNamespaces = "SOAP-ENV ec ec1 ns0 ns1 ns11 ns2 ns4 ns9";
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            transformer.engineCanonicalizeSubTree(document, inclusiveNamespaces, output);

            String result = new String(output.toByteArray(), UTF_8);
            assertEquals(message, result);
        }
    }
}
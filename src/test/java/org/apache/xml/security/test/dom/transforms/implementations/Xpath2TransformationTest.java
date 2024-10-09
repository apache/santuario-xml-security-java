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
package org.apache.xml.security.test.dom.transforms.implementations;


import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.testutils.Assertions;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPath2FilterContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.platform.commons.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the XPath2Transformation implementation
 *
 * @see <A HREF="http://www.w3.org/TR/xmldsig-filter2/">XPath Filter v2.0 (TR)</A>
 */
class Xpath2TransformationTest {
    private static final String TEST_PARAM_LIST_SEPARATOR = ";";
    private static final String TEST_PARAM_VALUE_SEPARATOR = "::";

    static {
        Init.init();
    }

    @Test
    void testXpath2Transform() throws Exception {
        String sig="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
        "<edoc:EDOC xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:edoc=\"http://www.imtf.com/hypersuite/edoc/2.0/\" sysid=\"CC9CC230-C0A8024E01A3CA10-AC154F78\">\r\n" +
        "   <edoc:Version>2.0</edoc:Version>\r\n" +
        "   <edoc:Object edocVersion=\"2.0\">\r\n" +
        "      <edoc:ObjectMetadata>\r\n" +
        "         <edoc:ObjectType>Record</edoc:ObjectType>\r\n" +
        "         <edoc:ObjectCreationDate>2004-12-13T14:27:35</edoc:ObjectCreationDate>\r\n" +
        "      </edoc:ObjectMetadata>\r\n" +
        "      <edoc:ObjectContent>\r\n" +
        "         <edoc:Record>\r\n" +
        "            <edoc:RecordMetadata></edoc:RecordMetadata>\r\n" +
        "            <edoc:Document id=\"Revision-1-Document-1\">\r\n" +
        "               <edoc:DocumentMetadata>\r\n" +
        "                  <dc:date>2003-07-20</dc:date>\r\n" +
        "                  <dc:type>20</dc:type>\r\n" +
        "                  <dc:format>PDF</dc:format>\r\n" +
        "                  <edoc:customer-number>222222</edoc:customer-number>\r\n" +
        "               </edoc:DocumentMetadata>\r\n" +
        "               <edoc:Encoding id=\"Revision-1-Document-1-Encoding-1\">\r\n" +
        "                  <edoc:EncodingMetadata>\r\n" +
        "                  </edoc:EncodingMetadata>\r\n" +
        "                  <edoc:ContentData encapsulation=\"Base64\" id=\"Revision-1-Document-1-Encoding-1-ContentData-1\" sourceFileSize=\"102550\">AAA</edoc:ContentData>\r\n" +
        "               </edoc:Encoding>\r\n" +
        "            </edoc:Document>\r\n" +
        "         </edoc:Record>\r\n" +
        "      </edoc:ObjectContent>\r\n" +
        "   </edoc:Object>\r\n" +
        "<edoc:SignatureBlock id=\"Revision-1-Signature-1\"><edoc:SignatureDate>2006-08-09T17:21:35</edoc:SignatureDate><edoc:Signer>Hess Yvan (first signature)</edoc:Signer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\r\n" +
        "<ds:SignedInfo>\r\n" +
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></ds:CanonicalizationMethod>\r\n" +
        "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></ds:SignatureMethod>\r\n" +
        "<ds:Reference URI=\"\">\r\n" +
        "<ds:Transforms>\r\n" +
        "<ds:Transform Algorithm=\"http://www.w3.org/2002/06/xmldsig-filter2\">\r\n" +
        "<dsig-xpath:XPath xmlns:dsig-xpath=\"http://www.w3.org/2002/06/xmldsig-filter2\" Filter=\"intersect\">/edoc:EDOC/edoc:Object</dsig-xpath:XPath>\r\n" +
        "</ds:Transform>\r\n" +
        "</ds:Transforms>\r\n" +
        "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></ds:DigestMethod>\r\n" +
        "<ds:DigestValue>YMXHTYArDBcWDG99epurfdSEAWM=</ds:DigestValue>\r\n" +
        "</ds:Reference>\r\n" +
        "</ds:SignedInfo>\r\n" +
        "<ds:SignatureValue>\r\n" +
        "Un2HBIOcwGe36k8eDEJISKP8/EmCp813JlmV0qqxIPVgdMsIJXR5Wky6uqwP+E3wAXj4NykW76GV\r\n" +
        "1eSD9dTKw/M/bFMbId0nBp0ZFaFE5DKU/My4956qr2oyJqiFRKOokCxds0jMQvGcKeWVC9oAROxR\r\n" +
        "byZQbrtjGw9YS+D5afY=\r\n" +
        "</ds:SignatureValue>\r\n" +
        "<ds:KeyInfo>\r\n" +
        "<ds:X509Data>\r\n" +
        "<ds:X509Certificate>\r\n" +
        "MIIDADCCAmmgAwIBAgIGAQpEtx7tMA0GCSqGSIb3DQEBBQUAMIGXMRQwEgYDVQQGEwtTd2l0emVy\r\n" +
        "bGFuZDERMA8GA1UECBMIRnJpYm91cmcxETAPBgNVBAcTCEdpdmlzaWV6MRUwEwYDVQQLEwxIeXBl\r\n" +
        "cnN1aXRlIDUxGTAXBgNVBAoTEEluZm9ybWF0aXF1ZS1NVEYxJzAlBgNVBAMTHklNVEYgUm9vdENl\r\n" +
        "cnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNjAzMjgyMjAwMDBaFw0xNjAzMTcyMzAwMDBaMIGMMRQw\r\n" +
        "EgYDVQQGEwtTd2l0emVybGFuZDERMA8GA1UECBMIRnJpYm91cmcxETAPBgNVBAcTCEdpdmlzaWV6\r\n" +
        "MRUwEwYDVQQLEwxIeXBlcnN1aXRlIDUxGTAXBgNVBAoTEEluZm9ybWF0aXF1ZS1NVEYxHDAaBgNV\r\n" +
        "BAMTE0lNVEYgRW5kQ2VydGlmaWNhdGUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOxpALzU\r\n" +
        "r8TjtFB7ghScWXdaDuHHRM7bPOoyuDSCxCznCBQitrwT/Un/vkZjDxSTG1bLWObqUMf1Yf6ul30n\r\n" +
        "nU9NsHO2fr7+YwtGnCV5vZ+qzWSQBY7qS+Gg8Ft9z0PluNRe84ukcQt7mdqSYet2qKbYWLP8tyFc\r\n" +
        "XCYs0JL5E6aTAgMBAAGjYDBeMB8GA1UdIwQYMBaAFIeIxHkuiPSRw5OArsqR7wZYgVPlMB0GA1Ud\r\n" +
        "DgQWBBRrfNhYheJHag+VBqDPWEOQyt3rqDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAN\r\n" +
        "BgkqhkiG9w0BAQUFAAOBgQB4OVKzObDkpadteusbvcEin2GdK3B2qz/HwqH07AEt/pQbJ/oQOsYL\r\n" +
        "qVyDFt3umJ5uHon15nkps3HRE4MoYNfVbtz1G+0nMcAbxVYJDIfC4YBJRUAm/aA0twfkiH6gFmLi\r\n" +
        "V8o5YRtkjXvZQKUtJ/Ps/m0DAC4A935jTHDd6F4FCw==\r\n" +
        "</ds:X509Certificate>\r\n" +
        "</ds:X509Data>\r\n" +
        "</ds:KeyInfo>\r\n" +
        "</ds:Signature></edoc:SignatureBlock></edoc:EDOC>";

        String correctC14n="<edoc:Object xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:edoc=\"http://www.imtf.com/hypersuite/edoc/2.0/\" edocVersion=\"2.0\">\n" +
        "      <edoc:ObjectMetadata>\n" +
        "         <edoc:ObjectType>Record</edoc:ObjectType>\n" +
        "         <edoc:ObjectCreationDate>2004-12-13T14:27:35</edoc:ObjectCreationDate>\n" +
        "      </edoc:ObjectMetadata>\n" +
        "      <edoc:ObjectContent>\n" +
        "         <edoc:Record>\n" +
        "            <edoc:RecordMetadata></edoc:RecordMetadata>\n" +
        "            <edoc:Document id=\"Revision-1-Document-1\">\n" +
        "               <edoc:DocumentMetadata>\n" +
        "                  <dc:date>2003-07-20</dc:date>\n" +
        "                  <dc:type>20</dc:type>\n" +
        "                  <dc:format>PDF</dc:format>\n" +
        "                  <edoc:customer-number>222222</edoc:customer-number>\n" +
        "               </edoc:DocumentMetadata>\n" +
        "               <edoc:Encoding id=\"Revision-1-Document-1-Encoding-1\">\n" +
        "                  <edoc:EncodingMetadata>\n" +
        "                  </edoc:EncodingMetadata>\n" +
        "                  <edoc:ContentData encapsulation=\"Base64\" id=\"Revision-1-Document-1-Encoding-1-ContentData-1\" sourceFileSize=\"102550\">AAA</edoc:ContentData>\n" +
        "               </edoc:Encoding>\n" +
        "            </edoc:Document>\n" +
        "         </edoc:Record>\n" +
        "      </edoc:ObjectContent>\n" +
        "   </edoc:Object>";

        org.w3c.dom.Document doc = null;
        try (ByteArrayInputStream is = new ByteArrayInputStream(sig.getBytes())) {
            doc = XMLUtils.read(is, false);
        }
        Element sigElement =
            (Element) doc.getElementsByTagNameNS(
                Constants.SignatureSpecNS, Constants._TAG_SIGNATURE).item(0);
        XMLSignature sign = new XMLSignature(sigElement, "");
        boolean verify =
            sign.checkSignatureValue(sign.getKeyInfo().getPublicKey());
        if (!verify) {
            for (int i = 0; i < sign.getSignedInfo().getLength(); i++) {
                boolean refVerify =
                    sign.getSignedInfo().getVerificationResult(i);
                if (!refVerify) {
                    byte[] contentBytes =
                        sign.getSignedInfo().item(i).getContentsAfterTransformation().getBytes();
                    assertEquals(
                        correctC14n,
                        new String(contentBytes)
                    );
                }
            }
        }
    }

    /**
     * Test the XPath2FilterContainer implementation with the example from the specification
     * <A HREF="https://www.w3.org/TR/xmldsig-filter2/#sec-Examples">4. Examples of Signature
     * Filter Transform Processing</A>
     *
     * @param xPathFilter the filter configuration as a string. The parameter is a list of
     *                    filters separated by ";" and each filter is a pair of filter type
     *                    and xpath separated by "::"
     * @param resultValidationXPath the expected nodes count for each xpath as a string.
     *                              The parameter is a list of xpaths  separated by ";"
     *                              and each xpath is a pair of xpath and expected
     *                              node count separated by "::"
     * @throws Exception if an error occurs while performing the transformation
     */
    @ParameterizedTest
    @CsvSource({
            "intersect:://ToBeSigned, //ToBeSigned::2;//Data::4",
            "intersect:://ToBeSigned;subtract:://NotToBeSigned, //ToBeSigned::2;//Data::2;//NotToBeSigned::0;//ReallyToBeSigned::0",
            "intersect:://ToBeSigned;subtract:://NotToBeSigned;union:://ReallyToBeSigned, //ToBeSigned::2;//Data::3;//NotToBeSigned::0;//ReallyToBeSigned::1",
    })
    void testXPath2TransformExample(String xPathFilter, String resultValidationXPath) throws Exception {
        Map<String, String> filterConfiguration = convertStringToMap(xPathFilter);
        Map<String, String> assertNodeCountByXPaths = convertStringToMap(resultValidationXPath);

        Document testDocument =  TestUtils.getTestDocumentFromResource("input-santuario-623.xml");
        // create Transform filter
        // create string array of [][] of filterConfiguration
        String[][] filterConfigurationArray = filterConfiguration.entrySet()
                .stream()
                .map(entry -> new String[]{entry.getKey(), entry.getValue()})
                .toArray(String[][]::new);

        NodeList xpathElements = XPath2FilterContainer.newInstances(testDocument, filterConfigurationArray);
        Transforms transforms = new Transforms(testDocument);
        transforms.addTransform(Transforms.TRANSFORM_XPATH2FILTER, xpathElements);

        // when: perform transformation
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLSignatureInput res = transforms.performTransforms(new XMLSignatureNodeInput(testDocument), os);

        // then: validate the result
        Document resultDocument = TestUtils.xmlFragmentToDocument(res.getBytes());
        Assertions.assertNodeCountForXPath(resultDocument, assertNodeCountByXPaths);
    }

    /**
     * Get map values from string where each entry is separated by "list separator" ';' and
     * key and value are separated by "value separator": '::'
     * @param input the input string to convert to map
     *              (e.g. "intersect:://ToBeSigned;subtract:://NotToBeSigned")
*    * @return the map of key value pairs.
     */
    private Map<String, String> convertStringToMap(String input) {
        if (StringUtils.isBlank(input)) {
            return Map.of();
        }

        String[] entries = input.split(TEST_PARAM_LIST_SEPARATOR);
        Map<String, String> map = new HashMap<>();
        for (String entry : entries) {
            String[] parts = entry.split(TEST_PARAM_VALUE_SEPARATOR);
            if (parts.length == 2) {
                map.put(parts[0], parts[1]);
            }
        }
        return map;
    }
}

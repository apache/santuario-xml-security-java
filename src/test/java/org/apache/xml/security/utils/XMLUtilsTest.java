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
package org.apache.xml.security.utils;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.soap.*;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XMLUtilsTest {

    @Test
    void protectAgainstWrappingAttackNodeWrappingOK() throws SOAPException {

        String elementId = "test:identifier";
        String serviceNS = "http://test-service";
        String elementWithUniqueId = "ElementWithUniqueId";

        SOAPMessage message = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL).createMessage();
        Element documentElement = message.getSOAPPart().getDocumentElement();

        SOAPHeaderElement soapHeader = message.getSOAPHeader().addHeaderElement(new QName(serviceNS, elementWithUniqueId));
        soapHeader.setAttributeNS(null, "id", elementId);
        soapHeader.setIdAttribute("id", true);

        boolean result = XMLUtils.protectAgainstWrappingAttack(documentElement, soapHeader, elementId);
        assertTrue(result);
    }

    @Test
    void protectAgainstWrappingAttackNodeWrappingFalse() throws SOAPException {

        String elementId = "test:identifier";
        String serviceNS = "http://test-service";
        String elementWithId = "ElementWithId";
        String elementWithDuplicateId = "ElementWithDuplicateId";

        SOAPMessage message = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL).createMessage();
        Element documentElement = message.getSOAPPart().getDocumentElement();

        SOAPHeaderElement soapHeader = message.getSOAPHeader().addHeaderElement(new QName(serviceNS, elementWithId));
        soapHeader.setAttributeNS(null, "id", elementId);
        soapHeader.setIdAttribute("id", true);

        SOAPHeaderElement soapHeaderDuplicate = message.getSOAPHeader().addHeaderElement(new QName(serviceNS, elementWithDuplicateId));
        soapHeaderDuplicate.setAttributeNS(null, "id", elementId);
        soapHeaderDuplicate.setIdAttribute("id", true);

        boolean result = XMLUtils.protectAgainstWrappingAttack(documentElement, soapHeader, elementId);
        assertFalse(result);
    }
}

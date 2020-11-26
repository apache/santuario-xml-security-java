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
package org.apache.xml.security.stax.ext;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.XMLSecurityEventReader;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Abstract class for SecurityHeaderHandlers with parse LOGic for the xml structures
 *
 */
public abstract class AbstractInputSecurityHeaderHandler implements XMLSecurityHeaderHandler {

    @SuppressWarnings("unchecked")
    protected <T> T parseStructure(final Deque<XMLSecEvent> eventDeque, final int index,
                                   final XMLSecurityProperties securityProperties) throws XMLSecurityException {
        try {
            Unmarshaller unmarshaller = XMLSecurityConstants.getJaxbUnmarshaller(securityProperties.isDisableSchemaValidation());
            return (T) unmarshaller.unmarshal(new XMLSecurityEventReader(eventDeque, index));

        } catch (JAXBException e) {
            if (e.getCause() != null && e.getCause() instanceof Exception) {
                throw new XMLSecurityException((Exception)e.getCause());
            }
            throw new XMLSecurityException(e);
        }
    }

    protected List<QName> getElementPath(Deque<XMLSecEvent> eventDeque) throws XMLSecurityException {
        XMLSecEvent xmlSecEvent = eventDeque.peek();
        return xmlSecEvent.getElementPath();
    }

    protected XMLSecEvent getResponsibleStartXMLEvent(Deque<XMLSecEvent> eventDeque, int index) {
        Iterator<XMLSecEvent> xmlSecEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < index) {
            xmlSecEventIterator.next();
        }
        return xmlSecEventIterator.next();
    }

    protected List<XMLSecEvent> getResponsibleXMLSecEvents(Deque<XMLSecEvent> xmlSecEvents, int index) {
        List<XMLSecEvent> xmlSecEventList = new ArrayList<>();

        Iterator<XMLSecEvent> xmlSecEventIterator = xmlSecEvents.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < index && xmlSecEventIterator.hasNext()) {
            xmlSecEventIterator.next();
        }

        while (xmlSecEventIterator.hasNext()) {
            xmlSecEventList.add(xmlSecEventIterator.next());
        }

        return xmlSecEventList;
    }
}

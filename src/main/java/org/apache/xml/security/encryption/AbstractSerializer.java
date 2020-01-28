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
package org.apache.xml.security.encryption;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Converts <code>String</code>s into <code>Node</code>s and visa versa.
 *
 * An abstract class for common Serializer functionality
 */
public abstract class AbstractSerializer implements Serializer {

    private final Canonicalizer canon;
    protected final boolean secureValidation;

    protected AbstractSerializer(String canonAlg, boolean secureValidation) throws InvalidCanonicalizerException {
        this.canon = Canonicalizer.getInstance(canonAlg);
        this.secureValidation = secureValidation;
    }

    /**
     * Returns a <code>byte[]</code> representation of the specified
     * <code>Element</code>.
     *
     * @param element the <code>Element</code> to serialize.
     * @return the <code>byte[]</code> representation of the serilaized
     *   <code>Element</code>.
     * @throws Exception
     */
    public byte[] serializeToByteArray(Element element) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            canon.canonicalizeSubtree(element, baos);
            return baos.toByteArray();
        }
    }

    /**
     * Returns a <code>byte[]</code> representation of the specified
     * <code>NodeList</code>.
     *
     * @param content the <code>NodeList</code> to serialize.
     * @return the <code>byte[]</code> representation of the serialized
     *   <code>NodeList</code>.
     * @throws Exception
     */
    public byte[] serializeToByteArray(NodeList content) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (int i = 0; i < content.getLength(); i++) {
                canon.canonicalizeSubtree(content.item(i), baos);
            }
            return baos.toByteArray();
        }
    }

    protected static byte[] createContext(byte[] source, Node ctx) throws XMLEncryptionException {
        // Create the context to parse the document against
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream, StandardCharsets.UTF_8);
            outputStreamWriter.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><dummy");

            // Run through each node up to the document node and find any xmlns: nodes
            Map<String, String> storedNamespaces = new HashMap<>();
            Node wk = ctx;
            while (wk != null) {
                NamedNodeMap atts = wk.getAttributes();
                if (atts != null) {
                    for (int i = 0; i < atts.getLength(); ++i) {
                        Node att = atts.item(i);
                        String nodeName = att.getNodeName();
                        if (("xmlns".equals(nodeName) || nodeName.startsWith("xmlns:"))
                                && !storedNamespaces.containsKey(att.getNodeName())) {
                            outputStreamWriter.write(" ");
                            outputStreamWriter.write(nodeName);
                            outputStreamWriter.write("=\"");
                            outputStreamWriter.write(att.getNodeValue());
                            outputStreamWriter.write("\"");
                            storedNamespaces.put(nodeName, att.getNodeValue());
                        }
                    }
                }
                wk = wk.getParentNode();
            }
            outputStreamWriter.write(">");
            outputStreamWriter.flush();
            byteArrayOutputStream.write(source);

            outputStreamWriter.write("</dummy>");
            outputStreamWriter.close();

            return byteArrayOutputStream.toByteArray();
        } catch (UnsupportedEncodingException e) {
            throw new XMLEncryptionException(e);
        } catch (IOException e) {
            throw new XMLEncryptionException(e);
        }
    }

}

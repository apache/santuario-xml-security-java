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
package org.apache.xml.security.test.dom.parser;


import java.io.InputStream;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.parser.XMLParserImpl;
import org.w3c.dom.Document;

/**
 * Override XMLParserImpl with a boolean check to make sure that we were actually called
 */
public class CustomXMLParserImpl extends XMLParserImpl {

    private static boolean called;

    @Override
    public Document parse(InputStream inputStream, boolean disAllowDocTypeDeclarations) throws XMLParserException {
        Document doc = super.parse(inputStream, disAllowDocTypeDeclarations);
        called = true;
        return doc;
    }

    public static boolean isCalled() {
        return called;
    }
}
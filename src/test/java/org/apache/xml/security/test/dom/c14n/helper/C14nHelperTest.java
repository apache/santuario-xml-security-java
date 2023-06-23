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
package org.apache.xml.security.test.dom.c14n.helper;


import java.lang.System.Logger;

import org.apache.xml.security.c14n.helper.C14nHelper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 */
class C14nHelperTest {

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * Method testNamespaceIsAbsolute01
     */
    @Test
    void testNamespaceIsAbsolute01() {

        String namespaceURI = "http://www.w3.org/Signature/";

        assertTrue(C14nHelper.namespaceIsAbsolute(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

    /**
     * @see <A HREF="http://lists.w3.org/Archives/Public/w3c-ietf-xmldsig/2001JulSep/0068.html">The list</A>
     */
    @Test
    void testNamespaceIsAbsolute02() {

        String namespaceURI = "http://www.w3.org/../blah";

        assertTrue(C14nHelper.namespaceIsAbsolute(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

    /**
     * Method testNamespaceIsAbsolute03
     */
    @Test
    void testNamespaceIsAbsolute03() {

        // unknown protocol?
        String namespaceURI = "hxxp://www.w3.org/";

        assertTrue(C14nHelper.namespaceIsAbsolute(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

    /**
     * Method testNamespaceIsRelative01
     */
    @Test
    void testNamespaceIsRelative01() {

        String namespaceURI = "../blah";

        assertTrue(C14nHelper.namespaceIsRelative(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

    /**
     * Method testNamespaceIsRelative02
     */
    @Test
    void testNamespaceIsRelative02() {

        String namespaceURI = "blah";

        assertTrue(C14nHelper.namespaceIsRelative(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

    /**
     * Method testNamespaceIsRelative03
     */
    @Test
    @Disabled
    void testNamespaceIsRelative03() {

        String namespaceURI = "http://...";

        assertTrue(C14nHelper.namespaceIsRelative(namespaceURI), "URI fails: \"" + namespaceURI + "\"");
    }

}
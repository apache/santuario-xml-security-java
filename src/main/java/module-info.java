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

/**
 * @author David Matejcek
 */
module org.apache.santuario.xmlsec {

    requires transitive jakarta.activation;
    requires transitive jakarta.xml.bind;
    requires java.base;
    requires java.management;
    requires java.xml;
    requires java.xml.crypto;
    requires org.apache.commons.codec;

    exports org.apache.jcp.xml.dsig.internal.dom;
    exports org.apache.xml.security;
    exports org.apache.xml.security.algorithms;
    exports org.apache.xml.security.algorithms.implementations;
    exports org.apache.xml.security.c14n;
    exports org.apache.xml.security.c14n.helper;
    exports org.apache.xml.security.c14n.implementations;
    exports org.apache.xml.security.configuration;
    exports org.apache.xml.security.encryption;
    exports org.apache.xml.security.encryption.keys;
    exports org.apache.xml.security.encryption.keys.content;
    exports org.apache.xml.security.encryption.keys.content.derivedKey;
    exports org.apache.xml.security.encryption.params;
    exports org.apache.xml.security.exceptions;
    exports org.apache.xml.security.keys;
    exports org.apache.xml.security.keys.content;
    exports org.apache.xml.security.keys.content.keyvalues;
    exports org.apache.xml.security.keys.content.x509;
    exports org.apache.xml.security.keys.keyresolver.implementations;
    exports org.apache.xml.security.keys.storage.implementations;
    exports org.apache.xml.security.signature;
    exports org.apache.xml.security.stax.ext;
    exports org.apache.xml.security.transforms;
    exports org.apache.xml.security.transforms.implementations;
    exports org.apache.xml.security.transforms.params;
    exports org.apache.xml.security.utils;
    exports org.apache.xml.security.utils.resolver;
    exports org.apache.xml.security.utils.resolver.implementations;

    opens org.apache.jcp.xml.dsig.internal.dom;
    opens org.apache.xml.security;
    opens org.apache.xml.security.binding.excc14n;
    opens org.apache.xml.security.binding.xmldsig;
    opens org.apache.xml.security.binding.xmldsig11;
    opens org.apache.xml.security.binding.xmlenc;
    opens org.apache.xml.security.binding.xmlenc11;
    opens org.apache.xml.security.binding.xop;
    opens org.apache.xml.security.configuration;
    opens org.apache.xml.security.algorithms.implementations;
    opens org.apache.xml.security.c14n.implementations;
    opens org.apache.xml.security.keys.keyresolver.implementations;
    opens org.apache.xml.security.keys.storage.implementations;
    opens org.apache.xml.security.transforms.implementations;
    opens org.apache.xml.security.utils.resolver.implementations;
}

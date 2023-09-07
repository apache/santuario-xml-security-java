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
package org.apache.xml.security.test.stax.utils;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

public class KeyLoader {

    private static final File DIR = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "keys", "content");

    public static PublicKey loadPublicKey(String fileName, String algorithm) throws Exception {
        String fileData = Files.readString(new File(DIR, fileName).toPath());
        byte[] keyBytes = XMLUtils.decode(fileData);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return kf.generatePublic(keySpec);
    }


    public static Document loadXML(String fileName) throws Exception {
        return XMLUtils.read(new File(DIR, fileName), false);
    }
}

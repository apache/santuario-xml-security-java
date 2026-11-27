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
package org.apache.xml.security.test.stax.encryption;

import java.nio.charset.StandardCharsets;

import org.apache.xml.security.stax.ext.stax.XMLSecCharacters;
import org.apache.xml.security.stax.impl.processor.output.AbstractEncryptOutputProcessor;
import org.apache.xml.security.stax.impl.processor.output.XMLEncryptOutputProcessor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The output stream that turns the base64 cipher text into character events must honour the
 * offset and length of write(byte[], int, int).
 */
class CharacterEventGeneratorOutputStreamTest {

    @Test
    void testWriteWithOffset() throws Exception {
        XMLEncryptOutputProcessor processor = new XMLEncryptOutputProcessor();
        byte[] bytes = "xxABCDEyy".getBytes(StandardCharsets.US_ASCII);
        StringBuilder written = new StringBuilder();
        try (AbstractEncryptOutputProcessor.CharacterEventGeneratorOutputStream out =
                 processor.new CharacterEventGeneratorOutputStream()) {
            out.write(bytes, 2, 5);
            out.write(bytes, 0, 2);
            out.write(bytes);

            for (XMLSecCharacters characters : out.getCharactersBuffer()) {
                written.append(characters.getText());
            }
        }
        assertEquals("ABCDE" + "xx" + "xxABCDEyy", written.toString());
    }
}

/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;

public class ArmorUtilsTest {

    @Test
    public void testParseArmorHeader() throws IOException {
        String armoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: BCPG v1.68\n" +
                "Hash: SHA512\n" +
                "Comment: This is a comment\n" +
                "Comment: This is another comment\n" +
                "\n" +
                "mDMEYJ/OsRYJKwYBBAHaRw8BAQdAaOs6IF1fWhN/dqwfSrxD/MNnBXVEx8WlecCa\n" +
                "cAiSCv60DnRlc3RAdGVzdC50ZXN0iHgEExYKACAFAmCfzrECGwMFFgIDAQAECwkI\n" +
                "BwUVCgkICwIeAQIZAQAKCRD2lyhrcqSwzDWIAP9i6LfaUp3gEhGQR3FojyhfPVB1\n" +
                "Y3bBU7osj/XOpEN6RAD/YzL9VO45yYp1IUvU1NQWJy42ZHHZy4ZrjULLQ/HbpQW4\n" +
                "OARgn86xEgorBgEEAZdVAQUBAQdASAPiuOakmDdL0HaSemeNB5Hl7lniD8vCeFgz\n" +
                "OcgWjSYDAQgHiHUEGBYKAB0FAmCfzrECGwwFFgIDAQAECwkIBwUVCgkICwIeAQAK\n" +
                "CRD2lyhrcqSwzJ4HAQD7uDYyEsqEGHI4LULfphxPSC5nG9pbBA3mL4ze46uDmAD/\n" +
                "aea172D0TfBwQXZxujLECTce5/1jyTaM+ee8gfw1BQ8=\n" +
                "=RQHd\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";

        ByteArrayInputStream in = new ByteArrayInputStream(armoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = new ArmoredInputStream(in);

        // No charset
        assertEquals(0, ArmorUtils.getCharsetHeaderValues(armorIn).size());

        // Version
        List<String> versionHeader = ArmorUtils.getVersionHeaderValues(armorIn);
        assertEquals(1, versionHeader.size());
        assertEquals("BCPG v1.68", versionHeader.get(0));

        // Hash
        List<String> hashHeader = ArmorUtils.getHashHeaderValues(armorIn);
        assertEquals(1, hashHeader.size());
        assertEquals("SHA512", hashHeader.get(0));
        List<HashAlgorithm> hashes = ArmorUtils.getHashAlgorithms(armorIn);
        assertEquals(HashAlgorithm.SHA512, hashes.get(0));

        // Comment
        List<String> commentHeader = ArmorUtils.getCommendHeaderValues(armorIn);
        assertEquals(2, commentHeader.size());
        assertEquals("This is a comment", commentHeader.get(0));
        assertEquals("This is another comment", commentHeader.get(1));

        // MessageID
        assertEquals(0, ArmorUtils.getMessageIdHeaderValues(armorIn).size());
    }
}

/**
 * Copyright 2016-2021 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.specification.nukleus.oauth.internal;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.Test;

public final class OAuthJwtKeysTest
{
    @Test
    public void shouldVerifyRSAKeyPair() throws Exception
    {
        KeyPair keyPair = OAuthJwtKeys.RFC7515_RS256;
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Random random = ThreadLocalRandom.current();
        byte[] challenge = new byte[32768];
        random.nextBytes(challenge);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();

        sig.initVerify(publicKey);
        sig.update(challenge);
        boolean verified = sig.verify(signature);

        assertTrue(verified);
    }

    @Test
    public void shouldVerifyECKeyPair() throws Exception
    {
        KeyPair keyPair = OAuthJwtKeys.RFC7515_ES256;
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Random random = ThreadLocalRandom.current();
        byte[] challenge = new byte[32768];
        random.nextBytes(challenge);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(challenge);
        byte[] signature = sig.sign();

        sig.initVerify(publicKey);
        sig.update(challenge);
        boolean verified = sig.verify(signature);

        assertTrue(verified);
    }
}

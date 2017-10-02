/**
 * Copyright 2016-2017 The Reaktivity Project
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
package org.reaktivity.specification.nukleus.auth.jwt.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.kaazing.k3po.lang.el.spi.FunctionMapperSpi;
import org.reaktivity.specification.auth.jwt.internal.Functions;

public final class FunctionsTest
{

    @Test
    public void shouldBase64Encode()
    {
        assertEquals("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
             Functions.base64Encode("{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"));
    }

    @Test
    public void shouldAppendStrings()
    {
        assertEquals("123456", Functions.append("1", "23", "456"));
    }

    @Test
    public void shouldCalculateSingleByteLengthUpTo255()
    {
        byte expected = (byte) 0xff;
        assertTrue(expected == Functions.length8(generateString(255)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotCalculateSingleByteLengthOfStringOver255()
    {
        byte expected = (byte) 0x80;
        assertTrue(expected == Functions.length8(generateString(256)));
    }

    public static class Mapper extends FunctionMapperSpi.Reflective
    {

        public Mapper()
        {
            super(FunctionsTest.class);
        }

        @Override
        public String getPrefixName()
        {
            return "jwt";
        }
    }

    private static String generateString(int length)
    {
        byte[] result = new byte[length];
        String alphabet = "1234567890";
        for (int i = 0; i < length; i++)
        {
            result[i] = (byte) alphabet.charAt(i % alphabet.length());
        }
        return new String(result);
    }
}

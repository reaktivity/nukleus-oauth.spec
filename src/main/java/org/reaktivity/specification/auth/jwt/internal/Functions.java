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
package org.reaktivity.specification.auth.jwt.internal;

import static java.lang.String.format;

import java.util.Base64;

import org.kaazing.k3po.lang.el.Function;
import org.kaazing.k3po.lang.el.spi.FunctionMapperSpi;

public final class Functions
{

    @Function
    public static String base64Encode(String value)
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes());
    }

    @Function
    public static String append(String... strings)
    {
        StringBuilder x = new StringBuilder();
        for (String s : strings)
        {
            x.append(s);
        }
        return x.toString();
    }

    @Function
    public static byte length8(String value)
    {
        int length = value.length();
        if (length > 0xFF)
        {
            throw new IllegalArgumentException(format("Length of \"%s\" cannot be expressed as a single byte", value));
        }
        return (byte) length;
    }

    public static class Mapper extends FunctionMapperSpi.Reflective
    {

        public Mapper()
        {
            super(Functions.class);
        }

        @Override
        public String getPrefixName()
        {
            return "jwt";
        }
    }

    private Functions()
    {
        // utility
    }
}

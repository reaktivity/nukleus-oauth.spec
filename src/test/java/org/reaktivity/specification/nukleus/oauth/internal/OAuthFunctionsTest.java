/**
 * Copyright 2016-2019 The Reaktivity Project
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.kaazing.k3po.lang.internal.el.ExpressionFactoryUtils.newExpressionFactory;
import static org.reaktivity.specification.nukleus.oauth.internal.OAuthJwtKeys.RFC7515_RS256;

import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;

import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.Before;
import org.junit.Test;
import org.kaazing.k3po.lang.internal.el.ExpressionContext;
import org.reaktivity.specification.oauth.internal.types.control.OAuthResolveExFW;

import java.security.GeneralSecurityException;

public final class OAuthFunctionsTest
{
    private ExpressionFactory factory;
    private ELContext ctx;

    @Before
    public void setUp() throws Exception
    {
        factory = newExpressionFactory();
        ctx = new ExpressionContext();
    }

    @Test
    public void shouldSignJWTwithRS256() throws GeneralSecurityException
    {
        String expressionText = OAuthFunctions.jwt("RS256")
                                              .expiresInSeconds(5)
                                              .claim("iss", "test issuer")
                                              .sign();
        ValueExpression expression = factory.createValueExpression(ctx, expressionText, String.class);
        String token = (String) expression.getValue(ctx);

        assertNotNull(token);
    }

    @Test
    public void shouldSignJWTwithES256() throws GeneralSecurityException
    {
        String expressionText = OAuthFunctions.jwt("ES256")
                                              .expiresInSeconds(5)
                                              .claim("iss", "test issuer")
                                              .sign();
        ValueExpression expression = factory.createValueExpression(ctx, expressionText, String.class);
        String token = (String) expression.getValue(ctx);

        assertNotNull(token);
    }

    @Test(expected = GeneralSecurityException.class)
    public void shouldFailSign() throws GeneralSecurityException
    {
        OAuthFunctions.jwt(RFC7515_RS256, "RS256", "wrong alg test")
                      .sign();
    }

    @Test(expected = AssertionError.class)
    public void shouldFailBadRIntegrity()
    {
        OAuthFunctions.decodeIntegrity(new byte[]{
                48, 69, 2, 33,
                // r
                1, -7, -33, 20, -11, -42, -105, -25, -46, -85, 76, -111, -100, -66, -80, 93, -83, -113, -40, -19, -41, -90, 108,
                -72, -71, -40, -112, -54, 113, 33, -84, -87, -103,
                2, 32,
                // s
                15, -114, -34, 122, -28, -122, 41, -47, 37, 32, 15, -32, -2, -111, -30, 20, -69, 41, 1, -84, -59, 7, -102, -39,
                -97, 63, -7, -60, -18, 0, -4, -30

        });
    }

    @Test(expected = AssertionError.class)
    public void shouldFailBadSIntegrity()
    {
        OAuthFunctions.decodeIntegrity(new byte[]{
                48, 69, 2, 32,
                // r
                127, -112, 89, -73, -40, -1, -33, -91, -127, -70, -87, -38, 61, 93, -30, -97, 49, 49, 90, 100, -1, -21, -37, -63,
                -24, -63, 22, 71, -17, -23, 49, -47,
                2, 33,
                // s
                127, -65, -40, -51, 77, -7, 90, -73, -34, -68, 75, -115, -117, 19, -13, 86, -42, -67, -41, 79, -117, 2, -14, 126,
                -66, 50, 121, 28, 79, 110, 8, 50, -36
        });
    }

    @Test
    public void shouldSupplyMapper()
    {
        assertEquals("oauth", new OAuthFunctions.Mapper().getPrefixName());
    }

    @Test
    public void shouldGenerateResolveExtension()
    {
        byte[] build = OAuthFunctions.resolveEx()
                                     .issuer("test issuer")
                                     .audience("test audience")
                                     .build();
        DirectBuffer buffer = new UnsafeBuffer(build);
        OAuthResolveExFW resolveEx = new OAuthResolveExFW().wrap(buffer, 0, buffer.capacity());

        assertEquals("test issuer", resolveEx.issuer().asString());
        assertEquals("test audience", resolveEx.audience().asString());
    }
}

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

import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;

import org.junit.Before;
import org.junit.Test;
import org.kaazing.k3po.lang.internal.el.ExpressionContext;

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
    public void shouldSignJWTwithRS256()
    {
        String expressionText = "${oauth:jwt(\"RS256\").claim(\"iss\", \"test issuer\").expiresInSeconds(5).sign()}";
        ValueExpression expression = factory.createValueExpression(ctx, expressionText, String.class);
        String token = (String) expression.getValue(ctx);

        assertNotNull(token);
    }

    @Test
    public void shouldSignJWTwithES256()
    {
        String expressionText = "${oauth:jwt(\"ES256\").claim(\"iss\", \"test issuer\").expiresInSeconds(5).sign()}";
        ValueExpression expression = factory.createValueExpression(ctx, expressionText, String.class);
        String token = (String) expression.getValue(ctx);

        assertNotNull(token);
    }

    @Test
    public void shouldSupplyMapper()
    {
        assertEquals("oauth", new OAuthFunctions.Mapper().getPrefixName());
    }
}

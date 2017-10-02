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
package org.reaktivity.specification.nukleus.auth.jwt.streams;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.specification.nukleus.NukleusRule;

public class ProxyConnectIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("streams", "org/reaktivity/specification/nukleus/auth/jwt/streams/proxy");

    private final TestRule timeout = new DisableOnDebug(new Timeout(5, SECONDS));

    private final NukleusRule nukleus = new NukleusRule()
            .directory("target/nukleus-itests");

    @Rule
    public final TestRule chain = outerRule(nukleus).around(k3po).around(timeout);

    @Test
    @Specification({
        "${streams}/request.with.invalid.jwt.forwarded/connect/client",
        "${streams}/request.with.invalid.jwt.forwarded/connect/server",
        })
    public void shouldForwardRequestWithInvalidJwtOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.valid.jwt.alg.none.forwarded/accept/client",
        "${streams}/request.with.valid.jwt.alg.none.forwarded/accept/server",
        })
    public void shouldForwardRequestWithValidJwtAlgNone() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.authorization.forwarded/connect/client",
        "${streams}/request.without.authorization.forwarded/connect/server",
        })
    public void shouldForwardRequestWithoutAuthorizationOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.bearer.forwarded/connect/client",
        "${streams}/request.without.bearer.forwarded/connect/server",
        })
    public void shouldForwardRequestWithoutBearerOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

}

/**
 * Copyright 2016-2018 The Reaktivity Project
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

public class ProxyAcceptIT
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
        "${streams}/proxy.accept.aborts/accept/client",
        "${streams}/proxy.accept.aborts/accept/server"
        })
    public void shouldAbortClientConnectWhenAcceptAborts() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/proxy.accept.reply.is.reset/accept/client",
        "${streams}/proxy.accept.reply.is.reset/accept/server"
        })
    public void shouldResetClientReplyWhenAcceptReplyIsReset() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/proxy.connect.is.reset/accept/client",
        "${streams}/proxy.connect.is.reset/accept/server"
        })
    public void shouldResetAcceptWhenConnectIsReset() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/proxy.connect.reply.aborts/accept/client",
        "${streams}/proxy.connect.reply.aborts/accept/server"
        })
    public void shouldAbortAcceptReplyWhenConnectReplyAborts() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.and.response.with.fragmented.data/accept/client",
        "${streams}/request.and.response.with.fragmented.data/accept/server"
        })
    public void shouldPropagateWindows() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.expired.jwt.forwarded/accept/client",
        "${streams}/request.with.expired.jwt.forwarded/accept/server"
        })
    public void shouldForwardRequestWithExpiredJwtOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.expired.jwt.no.route/accept/client",
        "${streams}/request.with.expired.jwt.no.route/accept/server"
        })
    public void shouldRejectRequestWithExpiredJwt() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.invalid.jwt.forwarded/accept/client",
        "${streams}/request.with.invalid.jwt.forwarded/accept/server"
        })
    public void shouldForwardRequestWithInvalidJwtOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.invalid.jwt.no.route/accept/client",
        "${streams}/request.with.invalid.jwt.no.route/accept/server"
        })
    public void shouldRejectRequestWithInvalidJwt() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.signed.jwt.es256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.es256.forwarded/accept/server"
        })
    public void shouldForwardRequestWithValidJwtEC256() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.signed.jwt.rs256.forwarded/accept/client",
        "${streams}/request.with.signed.jwt.rs256.forwarded/accept/server"
        })
    public void shouldForwardRequestWithValidJwtRS256() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.unready.jwt.forwarded/accept/client",
        "${streams}/request.with.unready.jwt.forwarded/accept/server"
        })
    public void shouldForwardRequestWithUnreadyJwtOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.unready.jwt.no.route/accept/client",
        "${streams}/request.with.unready.jwt.no.route/accept/server"
        })
    public void shouldRejectRequestWithUnreadyJwt() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.unsigned.jwt.forwarded/accept/client",
        "${streams}/request.with.unsigned.jwt.forwarded/accept/server"
        })
    public void shouldForwardRequestWithUnsignedJwtOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.with.unsigned.jwt.no.route/accept/client",
        "${streams}/request.with.unsigned.jwt.no.route/accept/server"
        })
    public void shouldRejectRequestWithUnsignedJwt() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.authorization.forwarded/accept/client",
        "${streams}/request.without.authorization.forwarded/accept/server"
        })
    public void shouldForwardRequestWithoutAuthorizationOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.authorization.no.route/accept/client",
        "${streams}/request.without.authorization.no.route/accept/server"
        })
    public void shouldRejectRequestWithoutAuthorization() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.bearer.forwarded/accept/client",
        "${streams}/request.without.bearer.forwarded/accept/server"
        })
    public void shouldForwardRequestWithoutBearerOnUnsecuredRoute() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

    @Test
    @Specification({
        "${streams}/request.without.bearer.no.route/accept/client",
        "${streams}/request.without.bearer.no.route/accept/server"
        })
    public void shouldRejectRequestWithoutBearer() throws Exception
    {
        k3po.start();
        k3po.notifyBarrier("ROUTED_PROXY");
        k3po.finish();
    }

}

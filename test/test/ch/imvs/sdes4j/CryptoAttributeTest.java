/*
 * SDES4J
 * Java implementation of SDES (Security Descriptions for Media Streams,
 * RFC 4568).
 * 
 * Copyright (C) 2011 FHNW
 *   University of Applied Sciences Northwestern Switzerland (FHNW)
 *   School of Engineering
 *   Institute of Mobile and Distributed Systems (IMVS)
 *   http://sdes4j.imvs.ch
 * 
 * Distributable under LGPL license, see terms of license at gnu.org.
 */
package test.ch.imvs.sdes4j;

import static org.junit.Assert.*;


import org.junit.Before;
import org.junit.Test;

import ch.imvs.sdes4j.CryptoAttribute;
import ch.imvs.sdes4j.KeyParam;
import ch.imvs.sdes4j.SessionParam;
import ch.imvs.sdes4j.srtp.FecOrderSessionParam;
import ch.imvs.sdes4j.srtp.NoAuthSessionParam;
import ch.imvs.sdes4j.srtp.SrtpCryptoSuite;
import ch.imvs.sdes4j.srtp.SrtpKeyParam;
import ch.imvs.sdes4j.srtp.SrtpSDesFactory;

public class CryptoAttributeTest {
    private SrtpSDesFactory f;

    @Before
    public void setUp() {
        f = new SrtpSDesFactory();
    }

    @Test
    public void testEncodeSessionParamsString() {
        byte[] bkey = new byte[]{0};
        SrtpCryptoSuite suite = f.createCryptoSuite(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
        SrtpKeyParam key = new SrtpKeyParam(
                SrtpKeyParam.KEYMETHOD_INLINE,
                bkey,
                0, 0, 0
        );
        CryptoAttribute a = new CryptoAttribute(
                1,
                suite,
                new KeyParam[] { key },
                new SessionParam[] {
                        new FecOrderSessionParam(FecOrderSessionParam.FEC_SRTP),
                        new NoAuthSessionParam()
                }
        );
        assertEquals(2, a.getSessionParams().length);
        assertEquals("FEC_ORDER=FEC_SRTP UNAUTHENTICATED_SRTP", a.getSessionParamsString());
    }

    @Test
    public void testEncodeKeyParamsString() {
        byte[] bkey = new byte[]{0};
        SrtpCryptoSuite suite = f.createCryptoSuite(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
        SrtpKeyParam key = new SrtpKeyParam(
                SrtpKeyParam.KEYMETHOD_INLINE,
                bkey,
                0, 0, 0
        );
        CryptoAttribute a = new CryptoAttribute(
                1,
                suite,
                new KeyParam[] { key, key },
                null
        );
        assertEquals(2, a.getKeyParams().length);
        assertEquals("inline:AA==;inline:AA==", a.getKeyParamsString());
        assertEquals(0, a.getSessionParams().length);
    }

    @Test
    public void testParseMultipleKeyParams() {
        CryptoAttribute a = CryptoAttribute.create("1 AES_CM_128_HMAC_SHA1_80 inline:AA==|2^20|1:4;inline:AA==;inline:AA==|1024", f);
        assertEquals(3, a.getKeyParams().length);

        SrtpKeyParam kp1 = (SrtpKeyParam) a.getKeyParams()[0];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp1.getKeyMethod());
        assertEquals(0x100000, kp1.getLifetime());
        assertEquals(1, kp1.getMki());
        assertEquals(4, kp1.getMkiLength());

        SrtpKeyParam kp2 = (SrtpKeyParam) a.getKeyParams()[1];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp2.getKeyMethod());
        assertEquals(0, kp2.getLifetime());
        assertEquals(0, kp2.getMki());
        assertEquals(0, kp2.getMkiLength());

        SrtpKeyParam kp3 = (SrtpKeyParam) a.getKeyParams()[2];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp3.getKeyMethod());
        assertEquals(1024, kp3.getLifetime());
        assertEquals(0, kp3.getMki());
        assertEquals(0, kp3.getMkiLength());

        assertEquals("inline:AA==|1048576|1:4;inline:AA==;inline:AA==|1024", a.getKeyParamsString());
    }

    @Test
    public void testParseExample1() {
        CryptoAttribute a = CryptoAttribute.create("1 AES_CM_128_HMAC_SHA1_80       inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 FEC_ORDER=FEC_SRTP", f);
        validateExample2(a);
    }

    @Test
    public void testParseExample1Xmpp() {
        CryptoAttribute a = CryptoAttribute.create("1", "AES_CM_128_HMAC_SHA1_80", "inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4", "FEC_ORDER=FEC_SRTP", f);
        validateExample2(a);
    }

    private void validateExample2(CryptoAttribute a) {
        assertEquals(1, a.getTag());
        assertEquals(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, a.getCryptoSuite().encode());
        assertEquals(1, a.getKeyParams().length);
        SrtpKeyParam kp = (SrtpKeyParam) a.getKeyParams()[0];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(0x100000, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(4, kp.getMkiLength());
        assertEquals(1, a.getSessionParams().length);
        assertEquals(FecOrderSessionParam.FEC_SRTP, ((FecOrderSessionParam) a.getSessionParams()[0]).getMode());
        assertEquals("FEC_ORDER=FEC_SRTP", a.getSessionParamsString());
    }

    @Test
    public void testParseExample2() {
        CryptoAttribute a = CryptoAttribute.create("2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm|2^20|1:4;inline:QUJjZGVmMTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5|2^20|2:4\t\tFEC_ORDER=FEC_SRTP", f);
        assertEquals(2, a.getTag());
        assertEquals(SrtpCryptoSuite.F8_128_HMAC_SHA1_80, a.getCryptoSuite().encode());
        assertEquals(2, a.getKeyParams().length);
        SrtpKeyParam kp1 = (SrtpKeyParam) a.getKeyParams()[0];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp1.getKeyMethod());
        assertEquals(0x100000, kp1.getLifetime());
        assertEquals(1, kp1.getMki());
        assertEquals(4, kp1.getMkiLength());
        assertEquals(1, ((SrtpKeyParam) a.getKeyParams()[0]).getMki());
        assertEquals(2, ((SrtpKeyParam) a.getKeyParams()[1]).getMki());
        assertEquals(1, a.getSessionParams().length);
        assertEquals(FecOrderSessionParam.FEC_SRTP, ((FecOrderSessionParam) a.getSessionParams()[0]).getMode());
    }

    @Test
    public void testParseExample3() {
        CryptoAttribute a = CryptoAttribute.create("1 AES_CM_128_HMAC_SHA1_80    inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:4", f);
        validateExample3(a);
    }

    @Test
    public void testParseExample3Xmpp() {
        CryptoAttribute a = CryptoAttribute.create("1", "AES_CM_128_HMAC_SHA1_80", "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:4", null, f);
        validateExample3(a);
    }

    @Test
    public void testParseExample3bXmpp() {
        CryptoAttribute a = CryptoAttribute.create("1", "AES_CM_128_HMAC_SHA1_80", "inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:4", "", f);
        validateExample3(a);
    }
    
    private void validateExample3(CryptoAttribute a) {
        assertEquals(1, a.getTag());
        assertEquals(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, a.getCryptoSuite().encode());
        assertEquals(1, a.getKeyParams().length);
        SrtpKeyParam kp = (SrtpKeyParam) a.getKeyParams()[0];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(0x100000, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(4, kp.getMkiLength());
        assertEquals(0, a.getSessionParams().length);
        assertEquals("inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|1048576|1:4", a.getKeyParamsString());
        assertEquals(null, a.getSessionParamsString());
    }

    @Test
    public void testCreateAttribute() {
        byte[] bkey = new byte[]{0};
        SrtpCryptoSuite suite = f.createCryptoSuite(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
        SrtpKeyParam key = new SrtpKeyParam(
                SrtpKeyParam.KEYMETHOD_INLINE,
                bkey,
                0, 0, 0
        );
        CryptoAttribute a = new CryptoAttribute(1, suite, new KeyParam[] { key }, null);
        assertEquals("1 AES_CM_128_HMAC_SHA1_80 inline:AA==", a.encode());
        assertEquals(0, a.getSessionParams().length);
    }
}

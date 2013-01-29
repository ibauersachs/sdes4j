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
import ch.imvs.sdes4j.srtp.FecOrderSessionParam;
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
    public void testParseExample1() {
        CryptoAttribute a = CryptoAttribute.create("1 AES_CM_128_HMAC_SHA1_80       inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 FEC_ORDER=FEC_SRTP", f);
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
        assertEquals(1, a.getTag());
        assertEquals(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80, a.getCryptoSuite().encode());
        assertEquals(1, a.getKeyParams().length);
        SrtpKeyParam kp = (SrtpKeyParam) a.getKeyParams()[0];
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(0x100000, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(4, kp.getMkiLength());
        assertEquals(0, a.getSessionParams().length);
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
    }
}

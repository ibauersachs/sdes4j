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
package test.ch.imvs.sdes4j.srtp;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import ch.imvs.sdes4j.srtp.SrtpCryptoAttribute;
import ch.imvs.sdes4j.srtp.SrtpCryptoSuite;
import ch.imvs.sdes4j.srtp.SrtpKeyParam;
import ch.imvs.sdes4j.srtp.SrtpSDesFactory;

public class SrtpCryptoAttributeTest {
    private SrtpSDesFactory f;

    @Before
    public void setUp() {
        f = new SrtpSDesFactory();
    }

    @Test
    public void testGetSessionParams(){
        byte[] bkey = new byte[]{0};
        SrtpCryptoSuite suite = f.createCryptoSuite(SrtpCryptoSuite.AES_CM_128_HMAC_SHA1_80);
        SrtpKeyParam key = new SrtpKeyParam(
                SrtpKeyParam.KEYMETHOD_INLINE,
                bkey,
                0, 0, 0
        );

        SrtpCryptoAttribute ca = new SrtpCryptoAttribute(1, suite, new SrtpKeyParam[] { key }, null);
        assertEquals(0, ca.getSessionParams().length);
    }
}

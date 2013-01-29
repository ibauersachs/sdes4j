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

import static org.junit.Assert.*;

import org.junit.Test;

import ch.imvs.sdes4j.srtp.KdrSessionParam;

public class KdrSessionParamTest {

    @Test
    public void testKdrSessionParamInt() {
        KdrSessionParam kdr0 = new KdrSessionParam(0);
        assertEquals(0, kdr0.getKeyDerivationRate());
        assertEquals(1, kdr0.getKeyDerivationRateExpanded());
        assertEquals("KDR=0", kdr0.encode());

        KdrSessionParam kdr1 = new KdrSessionParam(1);
        assertEquals(1, kdr1.getKeyDerivationRate());
        assertEquals(2, kdr1.getKeyDerivationRateExpanded());
        assertEquals("KDR=1", kdr1.encode());

        KdrSessionParam kdr24 = new KdrSessionParam(24);
        assertEquals(24, kdr24.getKeyDerivationRate());
        assertEquals(0x1000000, kdr24.getKeyDerivationRateExpanded());
        assertEquals("KDR=24", kdr24.encode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testKdrSessionParamIntInvalidLower() {
        new KdrSessionParam(-1);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testKdrSessionParamIntInvalidUpper() {
        new KdrSessionParam(25);
    }

    @Test
    public void testKdrSessionParamString() {
        String input0 = "KDR=0";
        KdrSessionParam kdr0 = new KdrSessionParam(input0);
        assertEquals(0, kdr0.getKeyDerivationRate());
        assertEquals(1, kdr0.getKeyDerivationRateExpanded());
        assertEquals(input0, kdr0.encode());

        String input1 = "KDR=1";
        KdrSessionParam kdr1 = new KdrSessionParam(input1);
        assertEquals(1, kdr1.getKeyDerivationRate());
        assertEquals(2, kdr1.getKeyDerivationRateExpanded());
        assertEquals(input1, kdr1.encode());

        String input24 = "KDR=24";
        KdrSessionParam kdr24 = new KdrSessionParam(input24);
        assertEquals(24, kdr24.getKeyDerivationRate());
        assertEquals(0x1000000, kdr24.getKeyDerivationRateExpanded());
        assertEquals(input24, kdr24.encode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testKdrSessionParamStringInvalidLower() {
        new KdrSessionParam("KDR=-1");
    }

    @Test(expected=IllegalArgumentException.class)
    public void testKdrSessionParamStringInvalidUpper() {
        new KdrSessionParam("KDR=25");
    }
}

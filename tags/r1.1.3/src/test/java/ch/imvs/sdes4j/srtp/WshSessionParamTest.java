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
package ch.imvs.sdes4j.srtp;

import static org.junit.Assert.*;

import org.junit.Test;

import ch.imvs.sdes4j.srtp.WshSessionParam;

public class WshSessionParamTest {
    @Test
    public void testWshSessionParamInt() {
        WshSessionParam wsh = new WshSessionParam(64);
        assertEquals(64, wsh.getWindowSizeHint());
        assertEquals("WSH=64", wsh.encode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testWshSessionParamIntLower() {
        new WshSessionParam(63);
    }

    @Test
    public void testWshSessionParamString() {
        String input = "WSH=64";
        WshSessionParam wsh = new WshSessionParam(input);
        assertEquals(64, wsh.getWindowSizeHint());
        assertEquals(input, wsh.encode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testWshSessionParamStringLower() {
        new WshSessionParam("WSH=63");
    }
}

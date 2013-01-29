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

import ch.imvs.sdes4j.srtp.PlainSrtcpSessionParam;

public class PlainSrtcpSessionParamTest {

    @Test
    public void testToString() {
        assertEquals("UNENCRYPTED_SRTCP", new PlainSrtcpSessionParam().encode());
    }

}

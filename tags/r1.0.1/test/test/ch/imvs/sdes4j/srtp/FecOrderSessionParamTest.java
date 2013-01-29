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

import ch.imvs.sdes4j.srtp.FecOrderSessionParam;

public class FecOrderSessionParamTest {
    @Test
    public void testFecOrderSessionParamInt() {
        FecOrderSessionParam fecSrtp = new FecOrderSessionParam(FecOrderSessionParam.FEC_SRTP);
        assertEquals(FecOrderSessionParam.FEC_SRTP, fecSrtp.getMode());

        FecOrderSessionParam srtpFec = new FecOrderSessionParam(FecOrderSessionParam.SRTP_FEC);
        assertEquals(FecOrderSessionParam.SRTP_FEC, srtpFec.getMode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testFecOrderSessionParamIntInvalid() {
        new FecOrderSessionParam(3);
    }

    @Test
    public void testFecOrderSessionParamString() {
        String input1 = "FEC_ORDER=FEC_SRTP";
        FecOrderSessionParam fecSrtp = new FecOrderSessionParam(input1);
        assertEquals(FecOrderSessionParam.FEC_SRTP, fecSrtp.getMode());
        assertEquals(input1, fecSrtp.encode());

        String input2 = "FEC_ORDER=SRTP_FEC";
        FecOrderSessionParam srtpFec = new FecOrderSessionParam(FecOrderSessionParam.SRTP_FEC);
        assertEquals(FecOrderSessionParam.SRTP_FEC, srtpFec.getMode());
        assertEquals(input2, srtpFec.encode());
    }
}

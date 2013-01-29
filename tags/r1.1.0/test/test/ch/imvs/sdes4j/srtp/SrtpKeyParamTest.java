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

import ch.imvs.sdes4j.srtp.SrtpKeyParam;

public class SrtpKeyParamTest {
    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamInvalidKeyMethod() {
        new SrtpKeyParam("invalid", null, 0, 0, 0);
    }

    @Test
    public void testSrtpKeyParamKeyOnly() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(0, kp.getLifetime());
        assertEquals(0, kp.getMki());
        assertEquals(0, kp.getMkiLength());
        assertEquals(input, kp.encode());
    }

    @Test
    public void testSrtpKeyParamKeyAndLifetimeNumeric() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1234";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(1234, kp.getLifetime());
        assertEquals(0, kp.getMki());
        assertEquals(0, kp.getMkiLength());
        assertEquals(input, kp.encode());
    }

    @Test
    public void testSrtpKeyParamKeyAndLifetimeExponential() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|2^10";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(1024, kp.getLifetime());
        assertEquals(0, kp.getMki());
        assertEquals(0, kp.getMkiLength());
        assertEquals("inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1024", kp.encode());
    }

    @Test
    public void testSrtpKeyParamKeyAndMki() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1:128";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(0, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(128, kp.getMkiLength());
        assertEquals(input, kp.encode());
    }

    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamKeyAndMkiLower() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1:0";
        new SrtpKeyParam(input);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamKeyAndMkiUpper() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1:129";
        new SrtpKeyParam(input);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamKeyAndMkiInvalidNoMki() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|:129";
        new SrtpKeyParam(input);
    }

    @Test(expected=ArrayIndexOutOfBoundsException.class)
    public void testSrtpKeyParamKeyAndMkiInvalidNoMkiLength() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1:";
        new SrtpKeyParam(input);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamKeyInvalidLifetime() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2||1:129";
        new SrtpKeyParam(input);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testSrtpKeyParamInvalidKey() {
        String input = "inline:{==";
        new SrtpKeyParam(input);
    }

    @Test
    public void testSrtpKeyParamKeyAndLifetimeNumericAndMki() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1234|1:1";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(1234, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(1, kp.getMkiLength());
        assertEquals(input, kp.encode());
    }

    @Test
    public void testSrtpKeyParamKeyAndLifetimeExponetialAndMki() {
        String input = "inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|2^10|1:1";
        SrtpKeyParam kp = new SrtpKeyParam(input);
        assertEquals(SrtpKeyParam.KEYMETHOD_INLINE, kp.getKeyMethod());
        assertEquals(30, kp.getKey().length);
        assertEquals(1024, kp.getLifetime());
        assertEquals(1, kp.getMki());
        assertEquals(1, kp.getMkiLength());
        assertEquals("inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1024|1:1", kp.encode());
    }
}

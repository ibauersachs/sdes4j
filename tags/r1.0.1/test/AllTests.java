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
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import test.ch.imvs.sdes4j.CryptoAttributeTest;
import test.ch.imvs.sdes4j.srtp.FecKeySessionParamTest;
import test.ch.imvs.sdes4j.srtp.FecOrderSessionParamTest;
import test.ch.imvs.sdes4j.srtp.KdrSessionParamTest;
import test.ch.imvs.sdes4j.srtp.NoAuthSessionParamTest;
import test.ch.imvs.sdes4j.srtp.PlainSrtcpSessionParamTest;
import test.ch.imvs.sdes4j.srtp.PlainSrtpSessionParamTest;
import test.ch.imvs.sdes4j.srtp.SrtpCryptoSuiteTest;
import test.ch.imvs.sdes4j.srtp.SrtpKeyParamTest;
import test.ch.imvs.sdes4j.srtp.WshSessionParamTest;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    FecKeySessionParamTest.class,
    FecOrderSessionParamTest.class,
    KdrSessionParamTest.class,
    NoAuthSessionParamTest.class,
    PlainSrtcpSessionParamTest.class,
    PlainSrtpSessionParamTest.class,
    SrtpCryptoSuiteTest.class,
    SrtpKeyParamTest.class,
    WshSessionParamTest.class,
    CryptoAttributeTest.class

})
public class AllTests {
    // the class remains completely empty, 
    // being used only as a holder for the above annotations
}
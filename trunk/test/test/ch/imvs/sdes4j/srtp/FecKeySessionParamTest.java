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

import static org.easymock.classextension.EasyMock.*;
import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ch.imvs.sdes4j.srtp.FecKeySessionParam;
import ch.imvs.sdes4j.srtp.SrtpKeyParam;

public class FecKeySessionParamTest {

    private SrtpKeyParam kp1;
    private SrtpKeyParam kp2;

    @Before
    public void setUp() {
        kp1 = createMock(SrtpKeyParam.class);
        kp2 = createMock(SrtpKeyParam.class);
    }

    @Test
    public void testFecKeySessionParamSrtpKeyParamArray() {
        expect(kp1.encode()).andReturn("KP1").anyTimes();
        expect(kp2.encode()).andReturn("KP2").anyTimes();
        replay(kp1, kp2);

        FecKeySessionParam fecOne = new FecKeySessionParam(new SrtpKeyParam[] { kp1 });
        assertEquals("FEC_KEY=KP1", fecOne.encode());

        FecKeySessionParam fecTwo = new FecKeySessionParam(new SrtpKeyParam[] { kp1, kp2 });
        assertEquals("FEC_KEY=KP1;KP2", fecTwo.encode());

        verify(kp1, kp2);
    }

    @Test
    public void testFecKeySessionParamString() {
        String oneKeyParam = "FEC_KEY=KP1";
        FecKeySessionParam fecKeyOne = new FecKeySessionParam(oneKeyParam){
            @Override
            protected SrtpKeyParam createSrtpKeyParam(String p) {
                SrtpKeyParam kp = createMock(SrtpKeyParam.class);
                expect(kp.encode()).andReturn(p).anyTimes();
                replay(kp);
                return kp;
            }
        };
        assertEquals(1, fecKeyOne.getKeyParams().length);
        assertEquals(oneKeyParam, fecKeyOne.encode());

        String twoKeyParam = "FEC_KEY=KP1;KP2";
        FecKeySessionParam fecKeyTwo = new FecKeySessionParam(twoKeyParam){
            @Override
            protected SrtpKeyParam createSrtpKeyParam(String p) {
                SrtpKeyParam kp = createMock(SrtpKeyParam.class);
                expect(kp.encode()).andReturn(p).anyTimes();
                replay(kp);
                return kp;
            }
        };
        assertEquals(2, fecKeyTwo.getKeyParams().length);
        assertEquals(twoKeyParam, fecKeyTwo.encode());
    }

    @Test
    public void testGetKeyParams() {
        FecKeySessionParam fecTwo = new FecKeySessionParam(new SrtpKeyParam[] { kp1, kp2 });
        assertEquals(2, fecTwo.getKeyParams().length);
        assertEquals(kp1, fecTwo.getKeyParams()[0]);
        assertEquals(kp2, fecTwo.getKeyParams()[1]);
    }
}
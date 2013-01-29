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

import java.util.LinkedList;
import java.util.List;

import ch.imvs.sdes4j.KeyParam;

/**
 * FEC_KEY signals the use of separate master key(s) for a Forward Error
 * Correction (FEC) stream.
 * 
 * @author Ingo Bauersachs
 */
public class FecKeySessionParam extends SrtpSessionParam {
    private SrtpKeyParam[] keyParams;

    /**
     * Creates a new instance of this class from known key parameters.
     * @param keyParams The key parameters to use for this FEC session parameter.
     */
    public FecKeySessionParam(SrtpKeyParam[] keyParams) {
        this.keyParams = keyParams;
    }

    /**
     * Creates a new instance of this class from the textual representation of the session parameter.
     * @param param The textual representation of the session parameter.
     */
    public FecKeySessionParam(String param) {
        String[] params = param.substring("FEC_KEY=".length()).split(";");
        List<KeyParam> keyParams = new LinkedList<KeyParam>();
        for (String p : params) {
            keyParams.add(createSrtpKeyParam(p));
        }
        this.keyParams = keyParams.toArray(new SrtpKeyParam[0]);
    }

    /**
     * Factory method to create the key parameter objects.
     * 
     * @param p The key parameter to parse.
     * @return The parsed key parameter.
     */
    protected SrtpKeyParam createSrtpKeyParam(String p) {
        return new SrtpKeyParam(p);
    }

    /**
     * Gets the key parameters of this session parameter.
     * @return The key parameters of this session parameter.
     */
    public SrtpKeyParam[] getKeyParams() {
        return keyParams;
    }

    public String encode() {
        StringBuilder sb = new StringBuilder();
        sb.append("FEC_KEY=");
        for (int i = 0; i < keyParams.length; i++) {
            sb.append(keyParams[i].encode());
            if (i < keyParams.length - 1)
                sb.append(';');
        }
        return sb.toString();
    }
}

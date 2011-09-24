package ch.imvs.sdes4j.srtp;

import ch.imvs.sdes4j.CryptoAttribute;

/**
 * Security descriptions attribute for SRTP media streams.
 * 
 * @author Ingo Bauersachs
 */
public class SrtpCryptoAttribute extends CryptoAttribute {
    SrtpCryptoAttribute(){
    }

    /**
     * Creates an SRTP crypto attribute from its textual representation.
     * 
     * @param encoded The textual representation of the attribute.
     * @return The parsed crypto data.
     */
    public static SrtpCryptoAttribute create(String encoded){
        return (SrtpCryptoAttribute)CryptoAttribute.create(encoded, new SrtpSDesFactory());
    }

    /**
     * Creates a crypto attribute from already instantiated objects.
     * 
     * @param tag identifier for this particular crypto attribute
     * @param cryptoSuite identifier that describes the encryption and
     *            authentication algorithms
     * @param keyParams one or more sets of keying material
     * @param sessionParams the additional key parameters
     */
    public SrtpCryptoAttribute(int tag, SrtpCryptoSuite cryptoSuite, SrtpKeyParam[] keyParams, SrtpSessionParam[] sessionParams) {
        this.tag = tag;
        this.cryptoSuite = cryptoSuite;
        this.keyParams = keyParams;
        this.sessionParams = sessionParams;
    }

    @Override
    public SrtpCryptoSuite getCryptoSuite() {
        return (SrtpCryptoSuite) super.getCryptoSuite();
    }

    @Override
    public SrtpKeyParam[] getKeyParams() {
        return (SrtpKeyParam[]) super.getKeyParams();
    }

    @Override
    public SrtpSessionParam[] getSessionParams() {
        return (SrtpSessionParam[]) super.getSessionParams();
    }
}

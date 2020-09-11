/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.internal;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;

/**
 * Implements a singleton serial number generator using SecureRandom. This generator generates random 8 octec (64 bits) serial numbers.
 * 
 * RFC3280 defines serialNumber be positive INTEGER, and X.690 defines INTEGER consist of one or more octets. X.690 also defines as follows:
 * 
 * If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
 * a) shall not all be ones; and b) shall not all be zero.
 * 
 * Therefore, minimum 8 octets value is 0080000000000000 and maximum value is 7FFFFFFFFFFFFFFF."
 * 
 * Therefore, minimum 4 octets value is 00800000 and maximum value is 7FFFFFFF."
 * 
 * X.690:
 * 
 * 8.3 Encoding of an integer value 8.3.1 The encoding of an integer value shall be primitive. The contents octets shall consist of one or more
 * octets. 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the
 * second octet: a) shall not all be ones; and b) shall not all be zero. NOTE – These rules ensure that an integer value is always encoded in the
 * smallest possible number of octets. 8.3.3 The contents octets shall be a two's complement binary number equal to the integer value, and consisting
 * of bits 8 to 1 of the first octet, followed by bits 8 to 1 of the second octet, followed by bits 8 to 1 of each octet in turn up to and including
 * the last octet of the contents octets. NOTE – The value of a two's complement binary number is derived by numbering the bits in the contents
 * octets, starting with bit 1 of the last octet as bit zero and ending the numbering with bit 8 of the first octet. Each bit is assigned a numerical
 * value of 2N, where N is its position in the above numbering sequence. The value of the two's complement binary number is obtained by summing the
 * numerical values assigned to each bit for those bits which are set to one, excluding bit 8 of the first octet, and then reducing this value by the
 * numerical value assigned to bit 8 of the first octet if that bit is set to one.
 * 
 * @version $Id: SernoGeneratorRandom.java 31966 2019-03-25 10:19:57Z anatom $
 */
public class SernoGeneratorRandom implements SernoGenerator {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SernoGeneratorRandom.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** RFC5280, section 4.1.2.2, specifies using max 20 octets for serial number */ 
    private static final int SERNO_MAX_LENGTH = 20;

    /** random generator algorithm, defaults to FIPS approve SHA1PRNG in constructor 
     * The algorithm is specified globally in CesecoreConfiguration.getCaSerialNumberAlgorithm() */
    private String algorithm;

    /** number of bytes to generate, fixed size serial numbers */
    private int noOctets;

    /** random generator */
    private SecureRandom random;

    /** A registry of Singleton instances, to handle multiple octet sizes simultaneously. */
    private static Map<Integer, SernoGeneratorRandom> instances = new HashMap<>();
    /**
     * Creates (if needed) a serial number generator and returns the object.
     *
     * @return An instance of the serial number generator.
     */
    public static synchronized SernoGenerator instance(Integer noOctets) {
        SernoGeneratorRandom instance = instances.get(noOctets);
        if (instance == null) {
            instance = new SernoGeneratorRandom(noOctets);
            instances.put(noOctets, instance);
        }
        return instance;
    }

    /** DO NOT USE: Protected only to do testing of this implementation
     * use {@link #instance(Integer)} instead
     */
    protected SernoGeneratorRandom(Integer noOctets) {
        if (log.isTraceEnabled()) {
            log.trace(">SernoGenerator()");
        }
        this.algorithm = CesecoreConfiguration.getCaSerialNumberAlgorithm();
        if (this.algorithm == null) {
            this.algorithm = "SHA1PRNG";
        }
        if ((noOctets > SERNO_MAX_LENGTH || noOctets < 0)) { // We allow 0 octets for testing
            throw new IllegalArgumentException("ca.serialnumberoctetsize must be between 0 and " + SERNO_MAX_LENGTH + " bytes for this serial number generator.");
        }
        this.noOctets = noOctets;        
        init();
        if (log.isTraceEnabled()) {
            log.trace("<SernoGenerator()");
        }
    }

    private void init() {
        // Init random number generator for random serial numbers. 
        // SecureRandom provides a cryptographically strong random number generator (CSPRNG).
        try {
            // Use a specified algorithm if ca.rngalgorithm is provided and it's not set to default
            if (!StringUtils.isEmpty(algorithm) && !StringUtils.containsIgnoreCase(algorithm, "default")) {
                random = SecureRandom.getInstance(algorithm);
                log.info("Using "+algorithm+" serialNumber RNG algorithm.");
            } else if (!StringUtils.isEmpty(algorithm) && StringUtils.equalsIgnoreCase(algorithm, "defaultstrong")) {
                // If defaultstrong is specified and we use >=JDK8 try the getInstanceStrong to get a guaranteed strong random number generator.
                // Note that this may give you a generator that takes >30 seconds to create a single random number. 
                // On JDK8/Linux this gives you a NativePRNGBlocking, while SecureRandom.getInstance() gives a NativePRNG.
                try {
                    final Method methodGetInstanceStrong = SecureRandom.class.getDeclaredMethod("getInstanceStrong");
                    random = (SecureRandom) methodGetInstanceStrong.invoke(null);
                    log.info("Using SecureRandom.getInstanceStrong() with " + random.getAlgorithm() + " for serialNumber RNG algorithm.");
                } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                    throw new IllegalStateException("SecureRandom.getInstanceStrong() is not available or failed invocation. (This method was added in Java 8.)");
                }
            } else if (!StringUtils.isEmpty(algorithm) && StringUtils.equalsIgnoreCase(algorithm, "default")) {
                // We entered "default" so let's use a good default SecureRandom this should be good enough for just about everyone (on Linux at least)
                // On Linux the default Java implementation uses the (secure) /dev/(u)random, but on windows something else
                // On JDK8/Linux this gives you a NativePRNG, while SecureRandom.getInstanceStrong() gives a NativePRNGBlocking.
                random = new SecureRandom();
                log.info("Using default " + random.getAlgorithm() + " serialNumber RNG algorithm.");
            }
        } catch (NoSuchAlgorithmException e) {
            //This state is unrecoverable, and since algorithm is set in configuration requires a redeploy to handle
            throw new IllegalStateException("Algorithm " + algorithm + " was not a valid algorithm.", e);
        }
        if (random == null) {
            //This state is unrecoverable, and since algorithm is set in configuration requires a redeploy to handle
            throw new IllegalStateException("Algorithm " + algorithm + " was not a valid algorithm.");
        }
        // Call nextBytes directly after in order to force seeding if not already done. SecureRandom typically seeds on first call.
        random.nextBytes(new byte[0]);
    }

    @Override
    public BigInteger getSerno() {
        // This is only for testing, if size is set to 0 we will generate random number
        // between 1 and 5, this will give collisions often...
        if (noOctets == 0) {
            final Random rand = new Random();
            return BigInteger.valueOf(rand.nextInt(4)+1); // value 1-5
        }
        while (true) {
             /*
                Note that initBitsOfEntropy are not left intact by the following subsequent filtering operations:
                - Values discarded to avoid encoding in less than noOctets (including zero value).
                - Serial numbers previously assigned to other certificates (filtered later, not here).
                So the real entropy provided for generated serial numbers is always less than initBitsOfEntropy.
                 */
            // initBitsOfEntropy is 1 less than octet size, because we always use positive integers, which in 
            // two complements representation always has the most significant bit 0, making 63 bits random
            int initBitsOfEntropy = noOctets * 8 - 1;
            // SecureRanom is thread safe. This will generate from (0 to 2^initBitsOfEntropy -1)
            final BigInteger serno = new BigInteger(initBitsOfEntropy, random);
            if (checkSernoValidity(serno)) {
                return serno;
            } else {
                String msg = intres.getLocalizedMessage("sernogenerator.discarding");
                log.info(msg);
            }
        }
    }

    /**
     * This validates that the argument is a non-zero number to be encoded (according to X.690, "8.3 Encoding of an
     * integer value") exactly in 'noOctets' bytes. For example, for an 8 bytes serial number it will validate that it
     * falls within the range 0080000000000000 - 7FFFFFFFFFFFFFFF (both inclusive).
     */
    protected boolean checkSernoValidity(final BigInteger serno) {
        return serno.compareTo(BigInteger.ZERO) != 0 && serno.bitLength() / 8 + 1 == noOctets;
    }

    @Override
    public int getNoSernoBytes() {
        return noOctets;
    }

    @Override
    public void setSeed(final long seed) {
        random.setSeed(seed);
    }

    @Override
    public void setAlgorithm(final String algo) throws NoSuchAlgorithmException {
        // Since re-initialization is expensive, we only do it if we changed the algo
        if (this.algorithm == null || !this.algorithm.equals(algo)) {
            this.algorithm = algo;
            // We must force re-init after choosing a new algorithm
            this.random = null;
            init();
        }
    }

    /** Available for testing so we can compare that we actually use what we think
     * @return the random generator algorithm as reported by the underlying Java random number generator.
     */
    protected String getAlgorithm() {
        return random.getAlgorithm();
    }

}

package org.cesecore.internal;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.Thread.State;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import org.apache.log4j.Logger;
import org.cesecore.util.SecureXMLDecoder;
import org.junit.Test;

/**
 * @version $Id: UpgradeableDataHashMapTest.java 34163 2020-01-02 15:00:17Z
 *     samuellb $
 */
public class UpgradeableDataHashMapTest {

    /** Ligger. */
  static final Logger LOG = Logger.getLogger(UpgradeableDataHashMapTest.class);

  /**
   * Test if UpgradeableDataHashMap is vulnerable to CVE-2010-4476 through the
   * XML Serialization we use for storing UpgradeableDataHashMap.
   *
   * <p>When "2.2250738585072012e-308" is converted to a float, the code toggles
   * between two values causing the the Thread to hang.
   *
   * <p>UpgradeableDataHashMap.VERSION is normally stored as a Float.
   */
  @Test
  public void testCVE20104476() {
    final String xmlWBadFloar =
        "<java version=\"1.6.0_21\" class=\"java.beans.XMLDecoder\">"
            + "<object class=\"java.util.HashMap\"><void method=\"put\">"
            + "<string>version</string><float>2.2250738585072012e-308</float>"
            + "</void></object></java>";
    final String xmlWBadderFloat =
        "<java version=\"1.6.0_21\" class=\"java.beans.XMLDecoder\">"
            + "<object class=\"java.util.HashMap\"><void method=\"put\">"
            + "<string>version</string><double>2.2250738585072012e-308</double>"
            + "</void></object></java>";
    final String failMessage =
        "JDK is vulnerable to CVE-2010-4476 (requires write access to EJBCA"
            + " database to exploit).";
    assertTrue(failMessage, new DecoderThread(xmlWBadFloar).execute());
    assertTrue(failMessage, new DecoderThread(xmlWBadderFloat).execute());
  }

  /** Separate thread for test that might hang. */
  class DecoderThread
      implements Runnable { // NOPMD this is a stand-alone test, not a part of a
    // JEE application
    /** XML. */
      private final String decodeXML;

    DecoderThread(final String adecodeXML) {
      this.decodeXML = adecodeXML;
    }

    protected boolean execute() {
      Thread t =
          new Thread(
              this); // NOPMD this is a stand-alone test, not a part of a JEE
      // application
      t.start();
      try {
        t.join(4000); // Wait 5 seconds for thread to complete
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
      if (!t.getState().equals(State.TERMINATED)) {
        t.interrupt();
        return false;
      }
      return true;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void run() {
      try (SecureXMLDecoder decoder =
          new SecureXMLDecoder(
              new java.io.ByteArrayInputStream(
                  decodeXML.getBytes(StandardCharsets.UTF_8)))) {
        final HashMap<Object, Object> h =
            (HashMap<Object, Object>) decoder.readObject();
        for (Object o : h.keySet()) {
          LOG.info(o.toString() + ": " + h.get(o));
        }
      } catch (IOException e) {
        LOG.error("Failed to decode XML", e);
        throw new IllegalStateException(e);
      }
    }
  }
}

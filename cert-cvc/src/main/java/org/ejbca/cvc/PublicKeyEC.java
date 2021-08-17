/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.jce.ECPointUtil;
import org.ejbca.cvc.exception.ConstructionException;

/**
 * Implements handling of a public key of Elliptic Curve type.
 *
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 */
public class PublicKeyEC extends CVCPublicKey implements ECPublicKey {

  static final long serialVersionUID = 1L; // TODO: Fix better value

  /** Byte value indicating the start of an uncompressed Point data array. */
  public static final byte UNCOMPRESSED_POINT_TAG = 0x04;

  /** Fields. */
  private static CVCTagEnum[] allowedFields =
      new CVCTagEnum[] {
        CVCTagEnum.OID,
        CVCTagEnum.MODULUS,
        CVCTagEnum.COEFFICIENT_A,
        CVCTagEnum.COEFFICIENT_B,
        CVCTagEnum.BASE_POINT_G,
        CVCTagEnum.BASE_POINT_R_ORDER,
        CVCTagEnum.PUBLIC_POINT_Y,
        CVCTagEnum.COFACTOR_F
      };

  @Override
  protected CVCTagEnum[] getAllowedFields() {
    return allowedFields;
  }

  /**
   * Creates an instance from a GenericPublicKeyField.
   *
   * @param genericKey Key
 * @throws ConstructionException fail
   * @throws NoSuchFieldException fail
   */
  public PublicKeyEC(final GenericPublicKeyField genericKey)
      throws ConstructionException, NoSuchFieldException {
    // Copy all fields for a PublicKeyEC
    addSubfield(genericKey.getSubfield(CVCTagEnum.OID));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.MODULUS));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COEFFICIENT_A));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COEFFICIENT_B));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.BASE_POINT_G));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.BASE_POINT_R_ORDER));
    addSubfield(genericKey.getSubfield(CVCTagEnum.PUBLIC_POINT_Y));
    addSubfield(genericKey.getOptionalSubfield(CVCTagEnum.COFACTOR_F));
  }

  /**
   * Creates an instance from an OIDField and a
   * java.security.interfaces.ECPublicKey.
   *
   * @param oid OID
   * @param pubKeyEC Key
   * @param authRole role of certificate holder. If null or 'CVCA' all subfields
   *     are added, otherwise only the required ones.
 * @throws ConstructionException fail
   */
  public PublicKeyEC(
      final OIDField oid,
      final ECPublicKey pubKeyEC,
      final AuthorizationRole authRole)
      throws ConstructionException {
    super();

    addSubfield(oid);

    ECParameterSpec ecParameterSpec = pubKeyEC.getParams();
    boolean addAllParams = (authRole == null || authRole.isCVCA());
    if (addAllParams) {
      ECField ecField = ecParameterSpec.getCurve().getField();
      if (ecField instanceof ECFieldFp) {
        ECFieldFp fp = (ECFieldFp) ecField;
        addSubfield(
            new ByteField(
                CVCTagEnum.MODULUS, trimByteArray(fp.getP().toByteArray())));
      }
      // TODO: Can ecField be of type ECFieldF2m? Then what is the modulus?

      addSubfield(
          new ByteField(
              CVCTagEnum.COEFFICIENT_A,
              trimByteArray(ecParameterSpec.getCurve().getA().toByteArray())));
      addSubfield(
          new ByteField(
              CVCTagEnum.COEFFICIENT_B,
              trimByteArray(ecParameterSpec.getCurve().getB().toByteArray())));
      addSubfield(
          new ByteField(
              CVCTagEnum.BASE_POINT_G,
              encodePoint(
                  ecParameterSpec.getGenerator(), ecParameterSpec.getCurve())));
      addSubfield(
          new ByteField(
              CVCTagEnum.BASE_POINT_R_ORDER,
              trimByteArray(ecParameterSpec.getOrder().toByteArray())));
    }

    addSubfield(
        new ByteField(
            CVCTagEnum.PUBLIC_POINT_Y,
            encodePoint(pubKeyEC.getW(), ecParameterSpec.getCurve())));

    if (addAllParams) {
      addSubfield(
          new IntegerField(
              CVCTagEnum.COFACTOR_F, ecParameterSpec.getCofactor()));
    }
  }

  /**
   * Creates an instance from an OIDField and a
   * java.security.interfaces.ECPublicKey. This seemingly redundant overloaded
   * constructor is for binary (.class file) backwards compatibility. It is NOT
   * deprecated to use these argument types.
 * @param oid OID
 * @param pubKeyEC Key
 * @param authRole Role
 * @throws ConstructionException fail
   */
  public PublicKeyEC(
      final OIDField oid,
      final ECPublicKey pubKeyEC,
      final AuthorizationRoleEnum authRole)
      throws ConstructionException {
    this(oid, pubKeyEC, (AuthorizationRole) authRole);
  }

  /**
   * Overridden method that enables us to control exactly which fields that are
   * included when DER-encoding. According to EAC Spec 1.11: CVCRequest must
   * contain all fields, CVCA-certificate may have all, others must only have
   * the required fields.
   */
  @Override
  protected List<CVCObject> getEncodableFields() {
    try {
      ArrayList<CVCObject> list = new ArrayList<CVCObject>();
      // This field is always present
      list.add(getSubfield(CVCTagEnum.OID));

      boolean addAllParams = false;

      // First of all we must have an ECParameterSpec to read from
      ECParameterSpec ecParameterSpec = getParams();
      if (ecParameterSpec != null) {
        AbstractSequence parent = getParent();
        if (parent != null
            && (parent.getTag() == CVCTagEnum.CERTIFICATE_BODY)) {
          try {
            CVCObject cvcObj =
                ((CVCertificateBody) parent)
                    .getOptionalSubfield(CVCTagEnum.HOLDER_AUTH_TEMPLATE);
            if (cvcObj == null) {
              // No HOLDER_AUTH_TEMPLATE - assumption: We're building a
              // CVCRequest
              addAllParams = true;
            } else {
              // HOLDER_AUTH_TEMPLATE exists, so it should be a CVCertificate.
              // Check if role
              // is CVCA
              AuthorizationField authField =
                  ((CVCAuthorizationTemplate) cvcObj).getAuthorizationField();
              addAllParams =
                  (authField != null && authField.getAuthRole().isCVCA());
            }
          } catch (NoSuchFieldException e) {
            // Nothing to do...
          }
        } else if (parent == null) {
          // This could be useful during development - enables DER-encoding of
          // the public
          // key alone
          addAllParams = true;
        }
      }
      if (addAllParams) {
        ECField ecField = ecParameterSpec.getCurve().getField();
        if (ecField instanceof ECFieldFp) {
          list.add(getSubfield(CVCTagEnum.MODULUS));
        }
        // TODO: Can ecField be of type ECFieldF2m? Then what is the modulus?

        list.add(getSubfield(CVCTagEnum.COEFFICIENT_A));
        list.add(getSubfield(CVCTagEnum.COEFFICIENT_B));
        list.add(getSubfield(CVCTagEnum.BASE_POINT_G));
        list.add(getSubfield(CVCTagEnum.BASE_POINT_R_ORDER));
      }

      // This field is always present
      list.add(getSubfield(CVCTagEnum.PUBLIC_POINT_Y));

      if (addAllParams) {
        list.add(getSubfield(CVCTagEnum.COFACTOR_F));
      }
      return list;
    } catch (NoSuchFieldException e) {
      // This instance has not been created correctly
      throw new IllegalStateException(e);
    }
  }

  @Override
  public String getAlgorithm() {
    return "ECDSA"; // BC supports both EC and ECDSA, Sun only EC
  }

  @Override
  public String getFormat() {
    return "CVC";
  }

  @Override
  public ECParameterSpec getParams() {
    // Fetch the subfields and construct the ECParameterSpec
    ECParameterSpec ecParameterSpec = null;
    ByteField modulus = (ByteField) getOptionalSubfield(CVCTagEnum.MODULUS);
    ByteField coefficientA =
        (ByteField) getOptionalSubfield(CVCTagEnum.COEFFICIENT_A);
    ByteField coefficientB =
        (ByteField) getOptionalSubfield(CVCTagEnum.COEFFICIENT_B);
    ByteField basePointG =
        (ByteField) getOptionalSubfield(CVCTagEnum.BASE_POINT_G);
    ByteField pointROrder =
        (ByteField) getOptionalSubfield(CVCTagEnum.BASE_POINT_R_ORDER);
    IntegerField cofactor =
        (IntegerField) getOptionalSubfield(CVCTagEnum.COFACTOR_F);

    if (modulus != null) {
      EllipticCurve curve =
          new EllipticCurve(
              // ECField2m ?
              new ECFieldFp(new BigInteger(1, modulus.getData())), // q
              new BigInteger(1, coefficientA.getData()), // a
              new BigInteger(1, coefficientB.getData())); // b

      ecParameterSpec =
          new ECParameterSpec(
              curve,
              ECPointUtil.decodePoint(curve, basePointG.getData()), // G
              new BigInteger(1, pointROrder.getData()), // n
              cofactor.getValue()); // h
    }
    return ecParameterSpec;
  }

  @Override
  public ECPoint getW() {
    try {
      ByteField publicPointY =
          (ByteField) getSubfield(CVCTagEnum.PUBLIC_POINT_Y);
      return decodePoint(publicPointY.getData());
    } catch (NoSuchFieldException e) {
      // This instance has not been created correctly
      throw new IllegalStateException(e);
    }
  }

  /**
   * Uncompressed encoding of a ECPoint according to BSI-TR-03111 chapter 3.1.1:
   * 0x04 || enc(X) || enc(Y).
   *
   * @param ecPoint the point to encode
   * @param curve the curve used to get the field size, or null. If curve is
   *     given we can accurately decide the field size. If null is given we take
   *     the field size to be the largest of affineX.length and affineY.length,
   *     which will work in the majority of cases but might randomly produce the
   *     wrong result (a chance of 1 over 2^16).
   * @return point
   */
  public static byte[] encodePoint(
      final ECPoint ecPoint, final EllipticCurve curve) {
    byte[] pointX = trimByteArray(ecPoint.getAffineX().toByteArray());
    byte[] pointY = trimByteArray(ecPoint.getAffineY().toByteArray());

    final int offset = 7;
    final int shift = 3;
    int n = 0;
    if (curve != null) {
      // get fieldsize in bytes (+7 to round up and >>3 to divide by 8)
      n = (curve.getField().getFieldSize() + offset) >> shift;
    } else {
      // Normally n is the curve field size and pointX and pointY has length n.
      // This will simply try to use this size in case we don't have access to
      // the
      // curve.
      n = pointX.length > pointY.length ? pointX.length : pointY.length;
    }

    // In case pointX.length or pointY.length greater
    // the points will be trimmed to the length n

    // pointX.length and pointY.length should be equal to n
    int paddingXLength = 0;
    int paddingYLength = 0;

    // If the length of x was smaller than n we need to pad x on the left with 0
    if (pointX.length < n) {
        paddingXLength = n - pointX.length;
    }

    // If the length of y was smaller than n we need to pad y on the left with 0
    if (pointY.length < n) {
        paddingYLength = n - pointY.length;
    }

    // the resulting array should be two times n (n << 1) plus 1
    byte[] encoded = new byte[1 + (n << 1)];
    // Initialize result with all zeros (needed for the padding)
    Arrays.fill(encoded, (byte) 0x00);

    // Add 0x04, required tag by the encoding
    encoded[0] = UNCOMPRESSED_POINT_TAG;

    System.arraycopy(
        pointX, 0, encoded, 1 + paddingXLength, n - paddingXLength);
    System.arraycopy(
        pointY, 0, encoded, 1 + n + paddingYLength, n - paddingYLength);

    return encoded;
  }

  /**
   * Decodes an uncompressed ECPoint. First byte must be 0x04, otherwise
   * IllegalArgumentException is thrown.
   *
   * @param data data
   * @return point
   */
  public static ECPoint decodePoint(final byte[] data) {
    if (data[0] != UNCOMPRESSED_POINT_TAG) {
      throw new IllegalArgumentException(
          "First byte must be 0x" + UNCOMPRESSED_POINT_TAG);
    }
    byte[] xEnc = new byte[(data.length - 1) / 2];
    byte[] yEnc = new byte[(data.length - 1) / 2];

    System.arraycopy(data, 1, xEnc, 0, xEnc.length);
    System.arraycopy(data, xEnc.length + 1, yEnc, 0, yEnc.length);

    return new ECPoint(new BigInteger(1, xEnc), new BigInteger(1, yEnc));
  }
}

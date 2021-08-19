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
package org.cesecore.keys.util;

import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;

/**
 * Call {@link #doSignTask(List, Provider, ISignOperation)} or {@link
 * #doSignTask(List, String, ISignOperation)} when you want to sign with any
 * working algorithm in the list. This is usable when working with HSMs.
 * Different HSMs may support different algorithms. Use this class when you just
 * want to sign with any algorithm supported by the HSM. Example of this: -
 * Signing of certificate to be used for the p11 certificate object
 * corresponding to the p11 key. - Signing of CSR when no particular algorithm
 * is required by the receiver. - Test signing, just checking that the key is
 * working.
 *
 * @version $Id: SignWithWorkingAlgorithm.java 24555 2016-10-21 13:42:23Z anatom
 *     $
 */
public final class SignWithWorkingAlgorithm {
  /** Log4j instance. */
  private static final Logger LOG =
      Logger.getLogger(SignWithWorkingAlgorithm.class);
/** Map. */
  private static final Map<Integer, SignWithWorkingAlgorithm> INSTANCE_MAP =
      new HashMap<>();
  /** Provider. */
  private final Provider provider;
  /** List of available algos. */
  private final List<String> availableSignAlgorithms;
  /** Alg. */
  private String signAlgorithm;
  /** Lock. */
  private final Lock lock;

  /**
   * Finds the registered provider from sProvider and calls {@link
   * #doSignTask(List, Provider, ISignOperation)}.
   *
   * @param availableSignAlgorithms algorithms to choose from.
   * @param sProvider provider name
   * @param operation operation the performs the signing, is an instance of
   *     ISignOperation for example KeyTools.SignDataOperation
   * @return true if the signing was done.
   * @throws NoSuchProviderException if the provider is not found.
   * @throws TaskWithSigningException thrown if {@link
   *     ISignOperation#taskWithSigning(String, Provider)} is failing.
   */
  public static boolean doSignTask(
      final List<String> availableSignAlgorithms,
      final String sProvider,
      final ISignOperation operation)
      throws NoSuchProviderException, TaskWithSigningException {
    final Provider provider = Security.getProvider(sProvider);
    if (provider == null) {
      throw new NoSuchProviderException();
    }
    return doSignTask(availableSignAlgorithms, provider, operation);
  }
  /**
   * First time each algorithm in availableSignAlgorithms are tried until the
   * {@link ISignOperation#taskWithSigning(String, Provider)} is successfully
   * completed. The working algorithm is saved after the first time. Succeeding
   * calls with same availableSignAlgorithms and provider will directly use the
   * algorithm that was working the first time.
   *
   * @param availableSignAlgorithms algorithms to choose from.
   * @param provider provider
   * @param operation operation that performs the signing
   * @return true if the signing was done.
   * @throws TaskWithSigningException thrown if {@link
   *     ISignOperation#taskWithSigning(String, Provider)} is failing.
   */
  public static boolean doSignTask(
      final List<String> availableSignAlgorithms,
      final Provider provider,
      final ISignOperation operation)
      throws TaskWithSigningException {
    final Integer mapKey =
        Integer.valueOf(
            availableSignAlgorithms.hashCode() ^ provider.hashCode());
    final SignWithWorkingAlgorithm instance;
    synchronized (INSTANCE_MAP) {
      final SignWithWorkingAlgorithm waitInstance = INSTANCE_MAP.get(mapKey);
      if (waitInstance == null) {
        instance =
            new SignWithWorkingAlgorithm(provider, availableSignAlgorithms);
        INSTANCE_MAP.put(mapKey, instance);
      } else {
        instance = waitInstance;
      }
    }
    return instance.tryOutWorkingAlgorithm(operation);
  }

  /**
   * @param aProvider Provider
   * @param theAvailableSignAlgorithms Algs
   */
  private SignWithWorkingAlgorithm(
      final Provider aProvider,
      final List<String> theAvailableSignAlgorithms) {
    this.provider = aProvider;
    this.lock = new ReentrantLock();
    this.availableSignAlgorithms = theAvailableSignAlgorithms;
  }

  private boolean tryOutWorkingAlgorithm(final ISignOperation operation)
      throws TaskWithSigningException {
    if (this.signAlgorithm != null) {
      operation.taskWithSigning(this.signAlgorithm, this.provider);
      return true;
    }
    this.lock.lock();
    try {
      if (this.signAlgorithm != null) {
        operation.taskWithSigning(this.signAlgorithm, this.provider);
        return true;
      }
      for (final String trySignAlgorithm : this.availableSignAlgorithms) {
        try {
          operation.taskWithSigning(trySignAlgorithm, this.provider);
        } catch (final Exception e) {
          LOG.info(
              String.format(
                  "Signature algorithm '%s' not working for provider '%s'."
                      + " Exception: %s",
                  trySignAlgorithm, this.provider, e.getMessage()));
          continue;
        }
        LOG.info(
            String.format(
                "Signature algorithm '%s' working for provider '%s'.",
                trySignAlgorithm, this.provider));
        this.signAlgorithm = trySignAlgorithm;
        return true; // NOPMD
      }
      LOG.info(
          String.format(
              "No valid signing algorithm found for the provider '%s'.",
              this.provider));
      return false;
    } finally {
      this.lock.unlock();
    }
  }
}

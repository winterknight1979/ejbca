/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.hardtoken.profiles;

import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.IOException;

import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Interface containing methods that need to be implemented in order 
 * to have a hard token profile contain PIN Envelope settings.
 * 
 * @version $Id: IPINEnvelopeSettings.java 22117 2015-10-29 10:53:42Z mikekushner $
 */

public interface IPINEnvelopeSettings {


	/**
	 * Constant indicating that no envelope should be printed.
	 */    
	public static int PINENVELOPETYPE_NONE = 0;
    /**
     * Constant indicating that a general envelope type should be printed.
     */    
    public static int PINENVELOPETYPE_GENERALENVELOBE = 1;
    
    /**      
     * @return the type of PIN envelope to print.
     */
    public abstract int getPINEnvelopeType();    

	/**      
	 * sets the pin envelope type.
	 * @param pinenvelopetype PIN
	 */
	public abstract void setPINEnvelopeType(int pinenvelopetype);    
    
    /**
     * @return the filename of the current PIN envelope template.
     */
    public abstract String getPINEnvelopeTemplateFilename();

	/**
	 * @param filename Sets the filename of the current PIN envelope template.
	 */    
	public abstract void setPINEnvelopeTemplateFilename(String filename);
    
    /**
     * @return the data of the PIN Envelope template.
     */
    public abstract String getPINEnvelopeData();
    
    /**
     * @param data Sets the data of the PIN envelope template.
     */
    public abstract void setPINEnvelopeData(String data);

    /**
     * @return the number of copies of this PIN Envelope that should be printed.
     */
    public abstract int getNumberOfPINEnvelopeCopies();

	/**
	 * @param copies Sets the number of copies of this PIN Envelope that should be printed.
	 */
	public abstract void setNumberOfPINEnvelopeCopies(int copies);

	/**
	 * @return the validity of the visual layout in days.
	 */
	public abstract int getVisualValidity();

	/**
	 * @param validity Sets the validity of the visual layout in days.
	 */
	public abstract void setVisualValidity(int validity);

   /**
    * Method that parses the template, replaces the userdata
    * and returning a printable byte array 
 * @param userdata User
 * @param pincodes PIN
 * @param pukcodes PUK
 * @param hardtokensn SN
 * @param copyoftokensn SN copt
 * @return Envelope
 * @throws IOException IO fail 
 * @throws PrinterException Printer fail
    */	
	public abstract Printable printPINEnvelope(EndEntityInformation userdata, 
	                                        String[] pincodes, String[] pukcodes,
	                                        String hardtokensn, String copyoftokensn) 
	                                          throws   IOException, PrinterException;
}


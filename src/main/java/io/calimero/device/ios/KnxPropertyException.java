/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2020 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package io.calimero.device.ios;

import io.calimero.KnxRuntimeException;
import io.calimero.cemi.CEMIDevMgmt;

/**
 * Thrown on problems during access of a KNX property.
 *
 * @author B. Malinowsky
 */
public class KnxPropertyException extends KnxRuntimeException
{
	private static final long serialVersionUID = 1L;

	private final int code;

	/**
	 * Constructs a new <code>KnxPropertyException</code> with the specified detail message, with unspecified error code
	 * ({@link CEMIDevMgmt.ErrorCodes#UNSPECIFIED_ERROR}).
	 *
	 * @param s the detail message
	 */
	public KnxPropertyException(final String s)
	{
		super(s);
		code = 0;
	}

	/**
	 * Constructs a new <code>KnxPropertyException</code> with the specified detail message and an error code indicating
	 * the problem during property access.
	 * <p>
	 * Within the library, for the status code one of the codes listed in CEMIDevMgmt.ErrorCodes is used.
	 *
	 * @param s the detail message
	 * @param errorCode the error code of this exception
	 */
	public KnxPropertyException(final String s, final int errorCode)
	{
		super(s + ", " + CEMIDevMgmt.getErrorMessage(errorCode));
		code = errorCode;
	}

	/**
	 * Returns the error code assigned to this exception. If this exception originates from within the library, the
	 * status code is one of the codes listed in CEMIDevMgmt.ErrorCodes.
	 *
	 * @return error code as int
	 */
	public final int errorCode()
	{
		return code;
	}
}

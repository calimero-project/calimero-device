/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2019 B. Malinowsky

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

package tuwien.auto.calimero.device;

import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;

/**
 * Result container for application layer service handlers.
 * <p>
 * This class is used for answering a service result back to the remote communication
 * partner.<br>
 * A service result is supplied either as byte array, formatted as required by the
 * application layer service, or as command in form of {@link ServiceResult#run()}
 * executed by the KNX device answering mechanism.
 *
 * @author B. Malinowsky
 */
public class ServiceResult implements Runnable
{
	static final ServiceResult Empty = new ServiceResult(new byte[0]);

	private final ReturnCode ret;
	private final byte[] data;
	final boolean compact;

	/**
	 * Creates a service result with no result data.
	 */
	public ServiceResult()
	{
		ret = ReturnCode.Success;
		data = null;
		compact = false;
	}

	/**
	 * Creates a service result holding the result data as byte array.
	 *
	 * @param result byte array containing the service result data, with
	 *        <code>result.length</code> equal to the length as expected by the
	 *        application layer service
	 */
	public ServiceResult(final byte... result)
	{
		this(result, false);
	}

	ServiceResult(final ReturnCode returnCode, final byte... result) {
		ret = returnCode;
		data = result;
		compact = false;
	}

	public ServiceResult(final byte[] result, final boolean compact)
	{
		if (result == null)
			throw new KNXIllegalArgumentException("no service result");
		ret = ReturnCode.Success;
		data = result;
		this.compact = compact;
	}

	/**
	 * Returns the result data of this service.
	 *
	 * @return the service result data (no copy), or <code>null</code> if not set
	 */
	public byte[] getResult()
	{
		return data;
	}

	@Override
	public void run() {}

	/**
	 * Returns the KNX message priority used for this service result, the default value is {@link Priority#LOW}.
	 *
	 * @return the priority of type {@link Priority}
	 */
	public Priority getPriority()
	{
		return Priority.LOW;
	}

	ReturnCode returnCode() { return ret; }
}

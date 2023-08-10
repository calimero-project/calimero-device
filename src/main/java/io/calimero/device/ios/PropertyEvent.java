/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2010, 2018 B. Malinowsky

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

import java.util.EventObject;

/**
 * Event with details about a KNX property update. Objects of this type are immutable.
 *
 * @author B. Malinowsky
 */
public class PropertyEvent extends EventObject
{
	private static final long serialVersionUID = 1L;

	private final InterfaceObject io;
	private final int pid;
	private final int start;
	private final int elems;
	private final byte[] data;

	/**
	 * Creates a new property event using the interface object index and the property data.
	 *
	 * @param source the interface object server instance processing the property updated
	 * @param io the interface object containing the property
	 * @param propertyId KNX property identifier
	 * @param start the start index of the updated property values in the property value data array
	 *        of the interface object
	 * @param elements the number of updated property values, i.e., the number of elements contained
	 *        in the <code>data</code> argument
	 * @param data the updated property values as byte array, a copy is created during event
	 *        construction
	 */
	public PropertyEvent(final InterfaceObjectServer source, final InterfaceObject io,
		final int propertyId, final int start, final int elements, final byte[] data)
	{
		super(source);
		this.io = io;
		pid = propertyId;
		this.start = start;
		elems = elements;
		this.data = data.clone();
	}

	/**
	 * Returns the interface object containing the KNX property.
	 *
	 * @return the interface object
	 */
	public final InterfaceObject getInterfaceObject()
	{
		return io;
	}

	/**
	 * Returns the KNX property identifier (PID).
	 *
	 * @return the PID as int
	 */
	public final int getPropertyId()
	{
		return pid;
	}

	/**
	 * Returns the updated property values as data array. The number of property elements contained
	 * in the data array is returned by {@link #getElements()}.
	 *
	 * @return a copy of updated property values as byte array
	 */
	public byte[] getNewData()
	{
		return data.clone();
	}

	/**
	 * Returns the start index for the updated property values in the interface object KNX property.
	 *
	 * @return start index as int
	 */
	public final int getStartIndex()
	{
		return start;
	}

	/**
	 * Returns the number of property values affected by the property update.
	 *
	 * @return the number of updated property values as int
	 */
	public final int getElements()
	{
		return elems;
	}
}

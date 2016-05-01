/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2016 B. Malinowsky

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

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.TransportLayer;

/**
 * Service interface for KNX application layer management services.
 * <p>
 * A {@link BaseKnxDevice} implements (or refers to) this interface to process and respond to
 * application layer management services requests originating from a remote communication partner.<br>
 * This enables a Calimero KNX device to be notified, respond to, and update its device state, as
 * part of KNX management services and management procedures.
 * <p>
 * The service interface uses {@link ServiceResult}s to hand back the results for any further
 * processing by the lower communication layers. Such a service result can provide its result either
 * in form of data, or alternatively as command executed via {@link ServiceResult#run()}.
 *
 * @see ServiceResult
 * @author B. Malinowsky
 */
public interface ManagementService
{
	/**
	 * Invoked for an application layer property read service.
	 * <p>
	 * For data result, expects the requested number of property values as byte array.<br>
	 * To indicate an (illegal) access problem, or protected memory, use a service result with a
	 * data byte array of length 0.
	 *
	 * @param objectIndex
	 * @param propertyId
	 * @param startIndex
	 * @param elements
	 * @return the service result with the requested property values
	 */
	ServiceResult readProperty(int objectIndex, int propertyId, int startIndex, int elements);

	/**
	 * Invoked for an application layer property write service.
	 *
	 * @param objectIndex
	 * @param propertyId
	 * @param startIndex
	 * @param elements
	 * @param data
	 * @return
	 */
	ServiceResult writeProperty(int objectIndex, int propertyId, int startIndex, int elements,
		byte[] data);

	/**
	 * Invoked for an application layer property description read service.
	 *
	 * @param objectIndex
	 * @param propertyId
	 * @param propertyIndex
	 * @return
	 */
	ServiceResult readPropertyDescription(int objectIndex, int propertyId, int propertyIndex);

	/**
	 * Invoked for an application layer memory read service.
	 * <p>
	 * The read memory bytes returned from this method is sent back to the client using a memory
	 * read response.
	 *
	 * @param startAddress
	 * @param bytes
	 * @return the service result with the requested memory data
	 */
	ServiceResult readMemory(int startAddress, int bytes);

	/**
	 * Invoked for an application layer memory write service.
	 *
	 * @param startAddress
	 * @param data
	 * @return
	 */
	ServiceResult writeMemory(int startAddress, byte[] data);

	ServiceResult readAddress();

	ServiceResult writeAddress(IndividualAddress newAddress);

	ServiceResult readAddressSerial(byte[] serialNo);

	ServiceResult writeAddressSerial(byte[] serialNo, IndividualAddress newAddress);

	ServiceResult readDomainAddress();

	ServiceResult readDomainAddress(byte[] domain, IndividualAddress startAddress, int range);

	// system broadcast to set domain address: a domain address is either 2 bytes for
	// KNX-PL110 or 6 bytes for KNX-RF
	ServiceResult writeDomainAddress(byte[] domain);

	/**
	 * Invoked for an application layer device descriptor read service.
	 * <p>
	 * Currently, two descriptor types are defined in KNX:<br>
	 * Structure of descriptor type 0:<br>
	 * | mask type (8 bit): Medium Type (4 bit), Firmware Type (4 bit) | firmware version (8 bit):
	 * version (4 bit), sub code (4 bit) |
	 * <p>
	 * Structure of descriptor type 1:<br>
	 * | application manufacturer (16 bit) | device type (16 bit) | version (8 bit) | link mgmt
	 * service support (2 bit) | logical tag (LT) base value (6 bit) | CI 1 (16 bit) | CI 2 (16 bit)
	 * | CI 3 (16 bit) | CI 4 (16 bit) |<br>
	 *
	 * @param type descriptor type, currently defined are types 0 and 2
	 * @return
	 */
	ServiceResult readDescriptor(int type);

	ServiceResult readADC(int channel, int consecutiveReads);

	ServiceResult keyWrite(int accessLevel, byte[] key);

	ServiceResult authorize(byte[] key);

	ServiceResult restart(boolean masterReset, int eraseCode, int channel);

	// a catch-all method for not specifically dispatched management services
	ServiceResult management(int svcType, byte[] asdu, KNXAddress dst, Destination respondTo, TransportLayer tl);

	/**
	 * Returns whether verify mode is enabled on this endpoint for certain management services
	 * requested by clients.
	 * <p>
	 * Verifying mode is used by services concerned with writing memory data, and specifies how the
	 * KNX device will respond to the service.
	 *
	 * @return <code>true</code> if verify mode is enabled, <code>false</code> otherwise
	 */
	boolean isVerifyModeEnabled();
}

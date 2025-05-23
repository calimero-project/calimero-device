/*
    Calimero 3 - A library for KNX network access
    Copyright (c) 2011, 2025 B. Malinowsky

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

package io.calimero.device;

import java.time.Duration;

import io.calimero.DeviceDescriptor;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.ReturnCode;
import io.calimero.SerialNumber;
import io.calimero.mgmt.Description;
import io.calimero.mgmt.Destination;
import io.calimero.mgmt.ManagementClient;
import io.calimero.mgmt.ManagementClient.EraseCode;
import io.calimero.mgmt.TransportLayer;

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
	 * @param remote remote endpoint
	 * @param objectIndex interface object index
	 * @param propertyId property identifier
	 * @param startIndex start index in the property value to start reading from
	 * @param elements number of elements to read
	 *
	 * @return the service result with the requested property values
	 */
	ServiceResult<byte[]> readProperty(Destination remote, int objectIndex, int propertyId, int startIndex, int elements);

	/**
	 * Invoked for an application layer property write service.
	 * @param remote remote endpoint
	 * @param objectIndex interface object index
	 * @param propertyId property identifier
	 * @param startIndex start index in the property value to start writing to
	 * @param elements number of elements to write
	 * @param data byte array containing property value data to write
	 *
	 * @return service result containing the appropriate {@link ReturnCode}
	 */
	ServiceResult<Void> writeProperty(Destination remote, int objectIndex, int propertyId, int startIndex, int elements,
			byte[] data);

	/**
	 * Invoked for an application layer property description read service.
	 * <p>
	 * The property of the object is addressed either with a the <code>propertyId</code> or with the
	 * <code>propertyIndex</code>. The property index is only used if the property identifier is 0, otherwise the index
	 * is ignored.
	 *
	 * @param objectIndex interface object index
	 * @param propertyId property identifier
	 * @param propertyIndex property index, starts with index 0 for the first property
	 * @return the service result containing the property description
	 */
	ServiceResult<Description> readPropertyDescription(int objectIndex, int propertyId, int propertyIndex);

	default ServiceResult<byte[]> functionPropertyCommand(final Destination remote, final int objectIndex, final int propertyId,
			final byte[] command) {
		return ServiceResult.empty();
	}

	default ServiceResult<byte[]> readFunctionPropertyState(final Destination remote, final int objectIndex, final int propertyId,
			final byte[] functionInput) {
		return ServiceResult.empty();
	}

	/**
	 * Invoked for an application layer memory read service, the bytes returned from this method are sent back to the
	 * client using a memory read response.
	 *
	 * @param startAddress the 16 bit start address to read memory
	 * @param bytes number of data bytes to read (with increasing addresses), <code>bytes &gt; 0</code>
	 * @return the service result with the requested memory data
	 */
	ServiceResult<byte[]> readMemory(int startAddress, int bytes);

	/**
	 * Invoked for an application layer memory write service.
	 *
	 * @param startAddress 16 bit start address to write memory
	 * @param data byte array containing the memory data to write
	 * @return service result containing the appropriate {@link ReturnCode}
	 */
	ServiceResult<Void> writeMemory(int startAddress, byte[] data);

	/**
	 * Reads the individual address of this device; only a device in programming mode shall send a response to this service.
	 *
	 * @return service result containing <code>true</code> if in programming mode, <code>false</code> otherwise
	 */
	ServiceResult<Boolean> readAddress();

	/**
	 * Assigns a new individual address to this device; a device shall only set its address if in programming mode.
	 *
	 * @param newAddress new device address
	 */
	void writeAddress(IndividualAddress newAddress);

	/**
	 * Reads the individual address from a device having the requested serial number; a device shall only return a
	 * service result on matching serial number.
	 *
	 * @param serialNo serial number
	 * @return service result containing <code>true</code> on matching serial number, <code>false</code> otherwise
	 */
	ServiceResult<Boolean> readAddressSerial(SerialNumber serialNo);

	/**
	 * Assigns a new individual address to a device with matching serial number; this device shall only set its address
	 * on matching serial number.
	 *
	 * @param serialNo serial number
	 * @param newAddress new device address
	 */
	void writeAddressSerial(SerialNumber serialNo, IndividualAddress newAddress);

	/**
	 * Reads the domain address of this device, if this device is in programming mode.
	 *
	 * @return service result containing <code>true</code> if in programming mode, <code>false</code> otherwise
	 */
	ServiceResult<Boolean> readDomainAddress();

	/**
	 * Reads the domain address of this device; only a device with the requested domain and within the address range
	 * shall respond to this service.
	 *
	 * @param domain domain address, address length is 2 bytes (KNX PL110)
	 * @param startAddress start address, lower bound of checked address range (inclusive)
	 * @param range address range, <code>(startAddress + range)</code> specifies the upper bound address (inclusive)
	 * @return service result containing <code>true</code> if the conditions apply, <code>false</code> otherwise
	 */
	ServiceResult<Boolean> readDomainAddress(byte[] domain, IndividualAddress startAddress, int range);

	/**
	 * Reads the domain address of this device; only a device having a domain address within the requested domain address
	 * range shall respond to this service.
	 *
	 * @param startDoA start domain address (inclusive), address length is 6 bytes (KNX RF)
	 * @param endDoA end domain address (inclusive), address length is 6 bytes (KNX RF)
	 * @return service result containing <code>true</code> if the conditions apply, <code>false</code> otherwise
	 */
	ServiceResult<Boolean> readDomainAddress(byte[] startDoA, byte[] endDoA);

	/**
	 * Assigns a new domain address to a device; only a device in programming mode shall set its domain.
	 *
	 * @param domain domain address, address length is either 2 bytes for KNX-PL110 or 6 bytes for KNX-RF
	 */
	void writeDomainAddress(byte[] domain);

	default ServiceResult<byte[]> readParameter(final int objectType, final int pid, final byte[] testInfo) {
		return ServiceResult.empty();
	}

	default void writeParameter(final int objectType, final int pid, final byte[] value) {}

	/**
	 * Invoked for an application layer device descriptor read service.

	 * @param type descriptor type, currently defined are types 0 and 2
	 * @return service result containing the device descriptor information
	 */
	ServiceResult<DeviceDescriptor> readDescriptor(int type);

	/**
	 * Reads the value of the A/D converter of this device.
	 *
	 * @param channel channel number of the A/D converter
	 * @param consecutiveReads number of consecutive converter read operations
	 * @return service result with the calculated A/D conversion value
	 */
	ServiceResult<Integer> readADC(int channel, int consecutiveReads);

	/**
	 * Modifies or deletes an authorization key associated to an access level of this device.
	 * <p>
	 * This request requires a remote communication partner granted equal or higher access rights than the access rights
	 * of the <code>accessLevel</code> to be modified (i.e. current level &lt;= level to change).
	 * @param remote remote endpoint
	 * @param accessLevel access level to modify
	 * @param key new key for the specified access level, or 0xFFFFFFFF to remove key
	 *
	 * @return service result with the specified access level
	 * @see #authorize(Destination, byte[])
	 */
	ServiceResult<Integer> writeAuthKey(Destination remote, int accessLevel, byte[] key);

	/**
	 * Authorizes a communication partner providing its authorization key to obtain a certain access level.
	 *
	 * @param remote remote endpoint
	 * @param key authorization key
	 * @return service result with granted access level, level is between 0 (maximum access rights) and 3 (i.e., minimum
	 *         access rights) or 0 (maximum access rights) and 15 (minimum access rights)
	 */
	ServiceResult<Integer> authorize(Destination remote, byte[] key);

	/**
	 * Restarts this device.
	 *
	 * @param masterReset perform a master reset of the controller
	 * @param eraseCode for a master reset, specifies the resources that shall be reset prior to restarting the device
	 * @param channel for a master reset, specifies the number of the application channel that shall be reset and the
	 *        application parameters set to default values; 0 is to clear all link information in the group address
	 *        table and group object association table and reset all application parameters. With erase codes
	 *        {@link EraseCode#ConfirmedRestart}, {@link EraseCode#ResetIndividualAddress}, and
	 *        {@link EraseCode#ResetApplicationProgram}, the channel number is fixed to {@code 0}.
	 * @return process time required for restarting the device, can be 0 if time is &le; 5 seconds
	 * @see ManagementClient#restart(Destination)
	 * @see ManagementClient#restart(Destination, int, int)
	 */
	ServiceResult<Duration> restart(boolean masterReset, EraseCode eraseCode, int channel);

	/**
	 * A catch-all method for not specifically dispatched management services.
	 *
	 * @param svcType management service type
	 * @param asdu ASDU
	 * @param dst destination address of the management service
	 * @param respondTo destination to respond to
	 * @param tl transport layer processing the management service
	 * @return service result with service response
	 */
	ServiceResult<byte[]> management(int svcType, byte[] asdu, KNXAddress dst, Destination respondTo, TransportLayer tl);

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

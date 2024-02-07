/*
    Calimero - A library for KNX network access
    Copyright (c) 2021, 2024 B. Malinowsky

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

import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.calimero.DeviceDescriptor;
import io.calimero.DeviceDescriptor.DD0;
import io.calimero.IndividualAddress;
import io.calimero.SerialNumber;
import io.calimero.mgmt.PropertyAccess;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.mgmt.PropertyClient.Property;
import io.calimero.mgmt.PropertyClient.PropertyKey;

/** Interface object of type 'device object' ({@link InterfaceObject#DEVICE_OBJECT}). */
public final class DeviceObject extends InterfaceObject {

	private static final int pidDownloadCounter = 30;
	private static final int pidRFDomainAddress = 82;

	public static DeviceObject lookup(final InterfaceObjectServer ios) { return ios.lookup(DEVICE_OBJECT, 1); }

	DeviceObject(final int index, final Map<PropertyKey, Property> definitions) {
		super(DEVICE_OBJECT, index, definitions);
	}

	public DeviceDescriptor.DD0 deviceDescriptor() { return DD0.from(get(PID.DEVICE_DESCRIPTOR)); }

	public IndividualAddress deviceAddress() {
		return new IndividualAddress(new byte[] { get(PID.SUBNET_ADDRESS)[0], get(PID.DEVICE_ADDRESS)[0] });
	}

	public void setDeviceAddress(final IndividualAddress address) {
		final byte[] addr = address.toByteArray();
		set(PID.SUBNET_ADDRESS, addr[0]);
		set(PID.DEVICE_ADDRESS, addr[1]);
	}

	public String description() {
		final var bytes = getProperty(PID.DESCRIPTION, 1, Integer.MAX_VALUE);
		return new String(bytes, StandardCharsets.ISO_8859_1);
	}

	public boolean programmingMode() { return (get(PID.PROGMODE)[0] & 0x01) == 0x01; }

	public int maxApduLength() { return (int) unsigned(get(PID.MAX_APDULENGTH)); }

	public int manufacturer() { return (int) unsigned(get(PID.MANUFACTURER_ID)); }

	public SerialNumber serialNumber() { return SerialNumber.from(get(PropertyAccess.PID.SERIAL_NUMBER)); }

	public byte[] domainAddress(final boolean rfMedium) {
		return get(rfMedium ? pidRFDomainAddress : PID.DOMAIN_ADDRESS);
	}

	public void setDomainAddress(final byte[] domain) {
		set(domain.length == 6 ? pidRFDomainAddress : PID.DOMAIN_ADDRESS, domain);
	}

	public long downloadCounter() { return unsigned(get(pidDownloadCounter)); }

	private byte[] get(final int pid) { return getProperty(pid, 1, 1); }

	public void set(final int pid, final byte... data) {
		final boolean changed = setProperty(pid, 1, 1, data, false);
		if (changed)
			firePropertyChanged(pid, 1, 1, data);
	}

	private static long unsigned(final byte[] data) {
		long l = 0;
		for (final byte b : data)
			l = (l << 8) + (b & 0xff);
		return l;
	}
}

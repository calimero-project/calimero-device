/*
    Calimero - A library for KNX network access
    Copyright (c) 2019, 2024 B. Malinowsky

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

package tuwien.auto.calimero.device.ios;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.knxnetip.KNXnetIPRouting;
import tuwien.auto.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;

public final class KnxipParameterObject extends InterfaceObject {
	public static final class Pid {
		private Pid() {}

		public static final int TunnelingAddresses = 79;

		public static final int BackboneKey = 91;
		public static final int DeviceAuth = 92; // PDT generic 16
		public static final int UserPwdHashes = 93; // PDT generic 16
		public static final int SecuredServiceFamilies = 94;
		public static final int LatencyTolerance = 95;
		public static final int SyncLatencyFraction = 96;
		public static final int TunnelingUsers = 97;
	}


	public static KnxipParameterObject lookup(final InterfaceObjectServer ios, final int objectInstance) {
		return ios.lookup(KNXNETIP_PARAMETER_OBJECT, objectInstance);
	}


	KnxipParameterObject(final int index, final Map<PropertyKey, Property> definitions) {
		super(KNXNETIP_PARAMETER_OBJECT, index, definitions);
	}

	public byte[] get(final int pid) { return get(pid, 1, Integer.MAX_VALUE); }

	public byte[] getOrDefault(final int pid, final byte[] defaultData) {
		try {
			return get(pid);
		}
		catch (final KnxPropertyException e) {
			return defaultData;
		}
	}

	public byte[] get(final int pid, final int start, final int elements) {
		return getProperty(pid, start, elements);
	}

	public void set(final int pid, final byte... data) { set(pid, 1, 1, data); }

	public void set(final int pid, final int start, final int elements, final byte... data) {
		final boolean strictMode = false;
		final boolean changed = setProperty(pid, start, elements, data, strictMode);
		if (changed)
			firePropertyChanged(pid, start, elements, data);
	}

	public void setInetAddress(final int pid, final InetAddress addr) { set(pid, addr.getAddress()); }

	public InetAddress inetAddress(final int pid) {
		try {
			return InetAddress.getByAddress(getProperty(pid, 1, 1));
		}
		catch (final UnknownHostException e) {
			throw new KnxPropertyException(String.format("parsing IP address of PID %d: %s", pid, e.getMessage()));
		}
	}

	public String friendlyName() {
		final var data = get(PID.FRIENDLY_NAME, 1, 30);
		final String s = new String(data, StandardCharsets.ISO_8859_1);
		final int end = s.indexOf(0);
		return s.substring(0, end == -1 ? data.length : end);
	}

	public void setFriendlyName(final String name) {
		// friendly name property entry is an array of 30 characters
		final byte[] data = Arrays.copyOf(name.getBytes(StandardCharsets.ISO_8859_1), 30);
		set(PID.FRIENDLY_NAME, 1, data.length, data);
	}

	public int deviceState() {
		return (int) unsigned(get(PID.KNXNETIP_DEVICE_STATE, 1, 1));
	}

	public List<IndividualAddress> additionalAddresses() {
		final List<IndividualAddress> list = new ArrayList<>();
		try {
			final byte[] data = get(PID.ADDITIONAL_INDIVIDUAL_ADDRESSES);
			final var buf = ByteBuffer.wrap(data);
			while (buf.hasRemaining())
				list.add(new IndividualAddress(buf.getShort() & 0xffff));
		}
		catch (final KnxPropertyException e) {}
		return list;
	}

	public boolean securedService(final ServiceFamily serviceFamily) {
		try {
			final long securedServices = unsigned(get(KnxipParameterObject.Pid.SecuredServiceFamilies));
			final boolean secured = ((securedServices >> serviceFamily.id()) & 0x01) == 0x01;
			return secured;
		}
		catch (final KnxPropertyException e) {
			return false;
		}
	}

	public void populateWithDefaults() {
		setInetAddress(PID.SYSTEM_SETUP_MULTICAST_ADDRESS, KNXnetIPRouting.DefaultMulticast);

		set(PID.KNXNETIP_DEVICE_STATE, (byte) 0);
		set(PID.QUEUE_OVERFLOW_TO_IP, fromWord(0));
		set(PID.MSG_TRANSMIT_TO_IP, new byte[4]);

		// 100 ms is the default busy wait time
		set(PID.ROUTING_BUSY_WAIT_TIME, fromWord(100));
	}

	private static byte[] fromWord(final int word) {
		return new byte[] { (byte) (word >> 8), (byte) word };
	}

	private static long unsigned(final byte[] data) {
		long l = 0;
		for (final byte b : data)
			l = (l << 8) + (b & 0xff);
		return l;
	}
}

/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2024, 2024 B. Malinowsky

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

import java.util.Map;

import io.calimero.GroupAddress;
import io.calimero.mgmt.PropertyAccess;
import io.calimero.mgmt.PropertyClient.Property;
import io.calimero.mgmt.PropertyClient.PropertyKey;

public final class RouterObject extends InterfaceObject {
	public static RouterObject lookup(final InterfaceObjectServer ios, final int objectInstance) {
		return ios.lookup(ROUTER_OBJECT, objectInstance);
	}


	RouterObject(final int index, final Map<PropertyKey, Property> definitions) {
		super(ROUTER_OBJECT, index, definitions);
	}

	public enum RoutingConfig {
		Reserved,
		All, // route all frames
		Block, // block all frames
		Route; // route based on dst IA and own address, or filter table for GAs

		public static RoutingConfig of(final int value) { return values()[value]; }
	}

	// forwarding settings for group communication
	public RoutingConfig routingLcGroupConfig(final boolean fromMain, final GroupAddress groupAddress) {
		// MAIN_X: defines the handling of frames from main line
		// SUB_X: defines the handling of frames from sub line
		final int pid = fromMain ? PropertyAccess.PID.MAIN_LCGROUPCONFIG : PropertyAccess.PID.SUB_LCGROUPCONFIG;

		// | Bit   |  7  6  5 |         4        |   3   2  |   1   0  |
		// | Name  | reserved | repeat if error? | ≥ 0x7000 | ≤ 0x6FFF |
		// handling of group addressed frames ≥ 0x7000 is in bits 2-3
		final int value = getProperty(pid, 1, 1)[0];
		return RoutingConfig.of((groupAddress.getRawAddress() <= 0x6fff ? value : (value >> 2)) & 0x03);
	}

	// forwarding settings for p2p frames
	public RoutingConfig routingLcConfig(final boolean fromMain) {
		final int pid = fromMain ? PropertyAccess.PID.MAIN_LCCONFIG : PropertyAccess.PID.SUB_LCCONFIG;
		final int value = getProperty(pid, 1, 1)[0];
		return RoutingConfig.of(value & 0x03);
	}

	// forwarding settings for broadcast frames
	public boolean broadcastLcConfig(final boolean fromMain) {
		final int pid = fromMain ? PropertyAccess.PID.MAIN_LCCONFIG : PropertyAccess.PID.SUB_LCCONFIG;
		final int value = getProperty(pid, 1, 1)[0];
		// bit 3 is broadcast lock: 1 = frames in broadcast communication mode will be blocked
		return (value & 0x08) == 0;
	}

	public void set(final int pid, final byte... data) { set(pid, 1, 1, data); }

	public void set(final int pid, final int start, final int elements, final byte... data) {
		final boolean strictMode = false;
		final boolean changed = setProperty(pid, start, elements, data, strictMode);
		if (changed)
			firePropertyChanged(pid, start, elements, data);
	}
}

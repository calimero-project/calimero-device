/*
    Calimero - A library for KNX network access
    Copyright (c) 2019, 2020 B. Malinowsky

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

import static tuwien.auto.calimero.device.ios.InterfaceObject.SECURITY_OBJECT;

import tuwien.auto.calimero.device.KnxDeviceServiceLogic.LoadState;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.mgmt.Description;

final class SecurityInterface {

	interface Pid {
		// Load Control (PDT CONTROL)
		int LoadstateControl = 5;

		// Security Mode (PDT FUNCTION)
		int SecurityMode = 51;

		// Point-to-point Key Table (PDT GENERIC_20[])
		int P2PKeyTable = 52;

		// Group Key Table (PDT GENERIC_18[])
		int GroupKeyTable = 53;

		// Security Individual Address Table (PDT GENERIC_08[])
		int SecurityIndividualAddressTable = 54;

		// Security Failures Log (PDT FUNCTION)
		int SecurityFailuresLog = 55;

		// Tool Key (PDT GENERIC_16)
		int ToolKey = 56;

		// Security Report (PDT BITSET8)
		int SecurityReport = 57;

		// Security Report Control (PDT BINARY_INFORMATION)
		int SecurityReportControl = 58;

		// Sequence Number Sending (PDT GENERIC_06)
		int SequenceNumberSending = 59;

		// LTE Mode Zone Key Table (PDT GENERIC19[])
		int ZoneKeyTable = 60;

		// Group Object Security Flags (PDT GENERIC_01[])
		int GOSecurityFlags = 61;

		// Role Table (PDT GENERIC_01[])
		int RoleTable = 62;


		// non-standardized

		// Sequence Number Sending (PDT GENERIC_06)
		int ToolSequenceNumberSending = 250;
	}

	private final InterfaceObjectServer ios;
	private final int objectInstance = 1;
	private final int objIndex;

	SecurityInterface(final InterfaceObjectServer ios) {
		this.ios = ios;
		final var interfaceObjects = ios.getInterfaceObjects();
		int index = 0;
		for (final var interfaceObject : interfaceObjects) {
			if (interfaceObject.getType() == SECURITY_OBJECT) {
				index = interfaceObject.getIndex();
				break;
			}
		}
		if (index == 0) {
			final var io = ios.addInterfaceObject(SECURITY_OBJECT);
			objIndex = io.getIndex();
			populateWithDefaults();
		}
		else
			objIndex = index;
	}

	byte[] get(final int pid) {
		return get(pid, 1, Integer.MAX_VALUE);
	}

	byte[] get(final int pid, final int start, final int elements) {
		return ios.getProperty(SECURITY_OBJECT, objectInstance, pid, start, elements);
	}

	void set(final int pid, final byte... data) {
		set(pid, 1, 1, data);
	}

	void set(final int pid, final int start, final int elements, final byte... data) {
		ios.setProperty(SECURITY_OBJECT, objectInstance, pid, start, elements, data);
	}

	private void populateWithDefaults() {
		set(Pid.LoadstateControl, (byte) LoadState.Loaded.ordinal());
		set(Pid.SecurityMode, (byte) 0);
		set(Pid.P2PKeyTable, 1, 0, new byte[0]);
		ios.setDescription(new Description(objIndex, SECURITY_OBJECT, Pid.GroupKeyTable, 0, 0, true, 0, 50, 3, 3),
				true);
		ios.setDescription(new Description(objIndex, SECURITY_OBJECT, Pid.SecurityIndividualAddressTable, 0, 0, true,
				0, 500, 3, 3), true);
		set(Pid.SecurityFailuresLog, 1, 1, new byte[8]);

		final byte[] toolkey = new byte[16];
		set(Pid.ToolKey, toolkey);

		set(Pid.SecurityReport, (byte) 0);
		set(Pid.SecurityReportControl, (byte) 1);
		set(Pid.SequenceNumberSending, new byte[6]);

		final int goFlags = 4000;
		set(Pid.GOSecurityFlags, 1, 4000, new byte[goFlags]);
		ios.setDescription(new Description(objIndex, SECURITY_OBJECT, Pid.GOSecurityFlags, 0, 0, true, 0, goFlags, 3, 3),
				true);

		set(Pid.RoleTable, 1, 0, new byte[0]);
	}
}

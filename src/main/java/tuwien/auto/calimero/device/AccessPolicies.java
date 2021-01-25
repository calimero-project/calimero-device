/*
    Calimero - A library for KNX network access
    Copyright (c) 2019, 2021 B. Malinowsky

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

import static java.util.Map.entry;

import java.util.Map;
import java.util.Set;

import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.SecurityControl;
import tuwien.auto.calimero.SecurityControl.DataSecurity;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.mgmt.ManagementClient.EraseCode;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;

public final class AccessPolicies {

	private static final int AuthorizeRequest = 0x03D1;
	private static final int DeviceDescriptorRead = 0x300;
	private static final int DomainAddressWrite = 0x3E0;
	private static final int DomainAddressRead = 0x3E1;
	private static final int DomainAddressSelectiveRead = 0x3E3;
	private static final int IndividualAddressRead = 0x0100;
	private static final int IndividualAddressSerialNumberRead = 0x03DC;
	private static final int IndividualAddressSerialNumberWrite = 0x03DE;
	private static final int IndividualAddressWrite = 0xC0;
	private static final int KeyWrite = 0x03D3;
	private static final int PropertyDescriptionRead = 0x03D8;
	private static final int PropertyExtDescriptionRead = 0b0111010010;

	//@formatter:off
	private static final Map<Integer, Integer> serviceLevelAccessPolicies = Map.ofEntries(
			entry(AuthorizeRequest,                   accessPolicy("2AA/2AA")),
			entry(DeviceDescriptorRead,               accessPolicy("155/155")),
			entry(DomainAddressRead,                  accessPolicy("155/155")),
			entry(DomainAddressWrite,                 accessPolicy("2AA/008")),
			entry(DomainAddressSelectiveRead,         accessPolicy("155/155")),
			entry(IndividualAddressRead,              accessPolicy("155/155")),
			entry(IndividualAddressSerialNumberRead,  accessPolicy("155/155")),
			entry(IndividualAddressSerialNumberWrite, accessPolicy("2AA/008")),
			entry(IndividualAddressWrite,             accessPolicy("2AA/008")),
			entry(KeyWrite,                           accessPolicy("2AA/008")),
			entry(PropertyDescriptionRead,            accessPolicy("155/155")),
			entry(PropertyExtDescriptionRead,         accessPolicy("155/155")));
	//@formatter:on

	private static int accessPolicy(final String accessPolicy) {
		final int slash = accessPolicy.indexOf('/');
		final int off = Integer.parseInt(accessPolicy.substring(0, slash), 16);
		final int on = Integer.parseInt(accessPolicy.substring(slash + 1), 16);
		if (off > 0x3ff || on > 0x3ff)
			throw new IllegalArgumentException("invalid access policy " + accessPolicy);
		return (off << 10) | on;
	}

	private static final Set<Integer> writeServices = Set.of(AuthorizeRequest, DomainAddressWrite,
			IndividualAddressSerialNumberWrite, IndividualAddressWrite, KeyWrite);

	static Map<PropertyKey, Property> definitions;

	// Role
	static final int Unlisted = 0;
	static final int RoleX = 1;
	static final int Tool = 2;

	// Security
	static final int None = 0;
	static final int AuthOnly = 1;
	static final int AuthConf = 2;

	// R/W/RW
	private static final int Read = 0b01;
	private static final int Write = 0b10;
	private static final int ReadWrite = 0b11;


	// service level access policies

	static boolean checkServiceAccess(final int service, final boolean securityMode,
			final SecurityControl securityCtrl) {
		final boolean write = AccessPolicies.writeServices.contains(service);
		if (write)
			return AccessPolicies.hasWriteAccess(service, securityMode, securityCtrl);
		return AccessPolicies.hasReadAccess(service, securityMode, securityCtrl);
	}

	private static boolean hasWriteAccess(final int service, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return (accessLevel(service, securityMode, securityCtrl) & Write) == Write;
	}

	private static boolean hasReadAccess(final int service, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return (accessLevel(service, securityMode, securityCtrl) & Read) == Read;
	}

	private static final int allAllowed = accessPolicy("3ff/3ff");

	private static int accessLevel(final int service, final boolean securityMode, final SecurityControl securityCtrl) {
		final int policy = serviceLevelAccessPolicies.getOrDefault(service, allAllowed);
		return readWrite(policy, securityMode, securityCtrl);
	}

	// data level access policies

	public static boolean checkPropertyAccess(final int objType, final int pid, final boolean read,
			final boolean securityMode, final SecurityControl securityCtrl) {
		final var key = pid <= 50 ? new PropertyKey(pid) : new PropertyKey(objType, pid);
		final var property = definitions.get(key);
		if (property == null) {
			if (objType == InterfaceObject.SECURITY_OBJECT)
				return false;
			return true;
		}

		final int policy = objType == InterfaceObject.SECURITY_OBJECT && pid == PID.LOAD_STATE_CONTROL
				? accessPolicy("00C/00C") : property.accessPolicy();
		if (policy == 0 && objType == InterfaceObject.SECURITY_OBJECT)
			return false;
		if (policy == 0)
			return true;

		final int rw = read ? Read : Write;
		return (readWrite(policy, securityMode, securityCtrl) & rw) == rw;
	}

	private static final int DoASerialNumberRead = 0b1111101100;
	private static final int DoASerialNumberWrite = 0b1111101110;

	boolean readDomainAddressSerial(final int service, final int domainSize, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return (doASerialAccessLevel(service, domainSize, securityMode, securityCtrl) & Read) == Read;
	}

	boolean writeDomainAddressSerial(final int service, final int domainSize, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return (doASerialAccessLevel(service, domainSize, securityMode, securityCtrl) & Write) == Write;
	}

	private static int doASerialAccessLevel(final int service, final int domainSize, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return readWrite(doASerialPolicy(service, domainSize), securityMode, securityCtrl);
	}

	private static int doASerialPolicy(final int service, final int doASize) {
		if (service != DoASerialNumberRead && service != DoASerialNumberWrite)
			throw new KNXIllegalArgumentException("unknown DoA S/N service " + Integer.toHexString(service));
		final boolean read = service == DoASerialNumberRead;
		switch (doASize) {
		case  2: return read ? 0x155155 : 0x2AA008;
		case  4: return read ? 0x000004 : 0x2AA008;
		case  6: return read ? 0x155155 : 0x2AA008;
		case 21: return read ? 0x004004 : 0x008008;
		default:
			throw new KNXIllegalArgumentException("unsupported DoA size " + doASize);
		}
	}

	static boolean checkRestartAccess(final boolean masterReset, final EraseCode code, final boolean securityMode,
			final SecurityControl securityCtrl) {
		return (restartAccess(masterReset, code, securityMode, securityCtrl) & Write) == Write;
	}

	private static int restartAccess(final boolean masterReset, final EraseCode code, final boolean securityMode,
			final SecurityControl securityCtrl) {
		if (!masterReset || (masterReset && code == EraseCode.ConfirmedRestart))
			return accessPolicy("2AA/0AA");
		if (securityMode && (code == EraseCode.ResetIndividualAddress || code == EraseCode.ResetApplicationProgram))
			throw new KNXIllegalArgumentException("unsupported restart service erase code " + code);
		return readWrite(accessPolicy("2AA/008"), securityMode, securityCtrl);
	}

	// resource allocation in bits for each role
	private static final int UnlistedBits = 2;
	private static final int RoleXBits = 4;
	private static final int ToolBits = 4;

	// bit offset into policy bitfield for unsecured security mode
	private static final int unsecuredModeOffset = UnlistedBits + RoleXBits + ToolBits;
	// relative bit offsets within (un)secured bitfield
	private static final int[] roleOffset = { RoleXBits + ToolBits, ToolBits, 0 };
	// relative bit offsets within a role
	private static final int[] securityOffset = { 0, 0, 2 };

	private static int readWrite(final int policy, final boolean securityMode, final SecurityControl securityCtrl) {
		final var sec = securityCtrl.security();
		final int role = sec == DataSecurity.None ? AccessPolicies.Unlisted
				: securityCtrl.toolAccess() ? AccessPolicies.Tool : AccessPolicies.RoleX;
		final int shift = (securityMode ? 0 : unsecuredModeOffset) + roleOffset[role] + securityOffset[sec.ordinal()];
		return (policy >> shift) & ReadWrite;
	}
}

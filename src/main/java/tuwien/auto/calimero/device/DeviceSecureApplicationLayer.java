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

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.IntUnaryOperator;

import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXIllegalArgumentException;
import tuwien.auto.calimero.KnxSecureException;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.SecurityControl;
import tuwien.auto.calimero.SecurityControl.DataSecurity;
import tuwien.auto.calimero.device.SecurityInterface.Pid;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.internal.Security;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.SecureManagement;
import tuwien.auto.calimero.mgmt.TransportLayerImpl;
import tuwien.auto.calimero.process.ProcessEvent;

final class DeviceSecureApplicationLayer extends SecureManagement {
	private static final int SeqSize = 6;
	private static final int KeySize = 16;

	private final BaseKnxDevice device;
	private final SecurityInterface securityInterface;

	@SuppressWarnings("serial")
	private final Set<byte[]> lastFailures = Collections.newSetFromMap(new LinkedHashMap<>() {
		protected boolean removeEldestEntry(final Map.Entry<byte[], Boolean> eldest) { return size() > 10; }
	});


	DeviceSecureApplicationLayer(final BaseKnxDevice device) {
		this(device, new SecurityInterface(device.getInterfaceObjectServer()));
	}

	private DeviceSecureApplicationLayer(final BaseKnxDevice device, final SecurityInterface securityInterface) {
		super((TransportLayerImpl) device.transportLayer(),
				device.getInterfaceObjectServer().getProperty(0, PropertyAccess.PID.SERIAL_NUMBER, 1, 1),
				unsigned(securityInterface.get(Pid.SequenceNumberSending)), Map.of());

		this.device = device;
		this.securityInterface = securityInterface;

		long toolSeqNo = 0;
		try {
			toolSeqNo = unsigned(securityInterface.get(Pid.ToolSequenceNumberSending));
		}
		catch (final KnxPropertyException ignore) {}
		if (toolSeqNo <= 1)
			resetToolAccessSequence();
		else
			updateSequenceNumber(true, toolSeqNo);

		// load failure log: property value = { 4 * counters (2 bytes each), last failures (12 bytes each) }
		final var failureLog = ByteBuffer.wrap(securityInterface.get(Pid.SecurityFailuresLog));
		initFailureCounter(InvalidScf, failureLog.getShort() & 0xffff);
		initFailureCounter(SeqNoError, failureLog.getShort() & 0xffff);
		initFailureCounter(CryptoError, failureLog.getShort() & 0xffff);
		initFailureCounter(AccessAndRoleError, failureLog.getShort() & 0xffff);
		while (failureLog.hasRemaining()) {
			final byte[] buf = new byte[12];
			failureLog.get(buf);
			lastFailures.add(buf);
		}

		Security.groupKeys().forEach(this::tryAddSecuredGroupAddress);
	}

	@Override
	public void close() {
		// persist failure log
		final var baos = new ByteArrayOutputStream();
		baos.writeBytes(failureCountersArray());
		lastFailures.forEach(baos::writeBytes);
		securityInterface.set(Pid.SecurityFailuresLog, baos.toByteArray());
	}

	@Override
	protected byte[] toolKey(final IndividualAddress addr) {
		return securityInterface.get(Pid.ToolKey);
	}

	@Override
	protected void updateSequenceNumber(final boolean toolAccess, final long seqNo) {
		super.updateSequenceNumber(toolAccess, seqNo);
		if (toolAccess)
			securityInterface.set(Pid.ToolSequenceNumberSending, sixBytes(seqNo).array());
		else
			securityInterface.set(Pid.SequenceNumberSending, sixBytes(seqNo).array());
	}

	@Override
	protected byte[] securityKey(final KNXAddress addr) {
		if (addr instanceof IndividualAddress) {
			final int indAddressIndex = indAddressIndex((IndividualAddress) addr);
			if (indAddressIndex > 0)
				return p2pKey(indAddressIndex);
			return null;
		}
		else {
			final int addressIndex = groupAddressIndex((GroupAddress) addr)
					.orElseThrow(() -> new KnxSecureException("no group key for " + addr));
			return groupKey(addressIndex);
		}
	}

	@Override
	protected void updateLastValidSequence(final boolean toolAccess, final IndividualAddress remote,
			final long seqNo) {
		if (toolAccess) {
			super.updateLastValidSequence(toolAccess, remote, seqNo);
		}
		else {
			final byte[] addresses = securityInterface.get(Pid.SecurityIndividualAddressTable);
			final int entrySize = 2 + SeqSize;
			final int idx = binarySearch(addresses, entrySize, 0, 2, remote.getRawAddress());
			if (idx >= 0) {
				final var data = ByteBuffer.allocate(8).put(remote.toByteArray()).put(sixBytes(seqNo));
				securityInterface.set(Pid.SecurityIndividualAddressTable, idx + 1, 1, data.array());
			}
		}
	}

	@Override
	protected long lastValidSequenceNumber(final boolean toolAccess, final IndividualAddress remote) {
		if (toolAccess)
			return super.lastValidSequenceNumber(toolAccess, remote);

		final byte[] addresses = securityInterface.get(Pid.SecurityIndividualAddressTable);
		final int entrySize = 2 + SeqSize;
		final int idx = binarySearch(addresses, entrySize, 0, 2, remote.getRawAddress());
		if (idx < 0)
			return 0;
		final int offset = idx * entrySize + 2;
		return unsigned(Arrays.copyOfRange(addresses, offset, offset + SeqSize));
	}

	// TODO check access group objects: failure counter is required

	@Override
	protected boolean checkAccess(final KNXAddress dst, final int service, final SecurityControl securityCtrl) {
		if (dst instanceof GroupAddress && service == ProcessServiceNotifier.GROUP_READ
				|| service == ProcessServiceNotifier.GROUP_WRITE) {
			final int goSecurity = groupObjectSecurity((GroupAddress) dst);
			final boolean conf = (goSecurity & 2) == 2;
			final boolean auth = (goSecurity & 1) == 1;
			final var required = SecurityControl.of(
					conf ? DataSecurity.AuthConf : auth ? DataSecurity.Auth : DataSecurity.None, false);
			// if group object security does not match exactly, complete service is ignored
			if (!securityCtrl.equals(required)) {
				device.logger().warn("group object {} security mismatch: requested {} but requires {}, ignore", dst,
						securityCtrl, required);
				return false;
			}
			return true;
		}

		return AccessPolicies.checkServiceAccess(service, isSecurityModeEnabled(), securityCtrl);
	}

	@Override
	protected int groupObjectSecurity(final GroupAddress group) {
		try {
			// security table uses same index as group object table
			return groupAddressIndex(group).flatMap(this::groupObjectIndex).map(this::groupObjectSecurity).orElse(0);
		}
		catch (final KnxPropertyException e) {
			return 0;
		}
	}

	@Override
	protected void securityFailure(final int errorType, final IntUnaryOperator updateFunction,
			final IndividualAddress src, final KNXAddress dst, final int ctrlExtended, final long seqNo) {
		super.securityFailure(errorType, updateFunction, src, dst, ctrlExtended, seqNo);

		if (src == null)
			return;
		final var buffer = ByteBuffer.allocate(12).put(src.toByteArray()).put(dst.toByteArray())
				.put((byte) ctrlExtended).put(sixBytes(seqNo)).put((byte) errorType);
		lastFailures.add(buffer.array());
	}

	boolean isSecurityModeEnabled() {
		return securityInterface.get(Pid.SecurityMode, 1, 1)[0] == 1;
	}

	void setSecurityMode(final boolean secure) {
		securityInterface.set(Pid.SecurityMode, (byte) (secure ? 1 : 0));
	}

	byte[] decrypt(final ProcessEvent pe) throws GeneralSecurityException {
		final int tpci = 0x00 | (SecureService >> 8);
		return decrypt(pe.getSourceAddr(), pe.getDestination(), tpci, pe.getASDU()).apdu();
	}

	ServiceResult securityMode(final boolean command, final byte[] functionInput) {
		final int serviceId = functionInput[1] & 0xff;
		if (serviceId != 0)
			return ServiceResult.error(ReturnCode.InvalidCommand);

		if (command && functionInput.length == 3) {
			final int mode = functionInput[2] & 0xff;
			if (mode > 1)
				return ServiceResult.error(ReturnCode.DataVoid);
			setSecurityMode(mode == 1);
			return new ServiceResult((byte) serviceId);
		}
		else if (!command && functionInput.length == 2) {
			return new ServiceResult(new byte[] { (byte) serviceId, (byte) (isSecurityModeEnabled() ? 1 : 0) });
		}
		return ServiceResult.error(ReturnCode.Error);
	}

	ServiceResult securityFailuresLog(final boolean command, final byte[] functionInput) {
		if (functionInput.length != 3)
			return ServiceResult.error(ReturnCode.DataVoid);

		final int id = functionInput[1] & 0xff;
		final int info = functionInput[2] & 0xff;
		if (command) {
			if (id == 0 && info == 0) {
				clearFailureLog();
				return new ServiceResult((byte) id);
			}
		}
		else {
			// failure counters
			if (id == 0 && info == 0) {
				final var counters = ByteBuffer.allocate(10).put((byte) id).put((byte) info).put(failureCountersArray());
				return new ServiceResult(counters.array());
			}
			// query latest failure by index
			else if (id == 1) {
				final int index = info;
				int i = 0;
				for (final var msgInfo : lastFailures) {
					if (i++ == index)
						return new ServiceResult(ByteBuffer.allocate(2 + msgInfo.length).put((byte) id)
								.put((byte) index).put(msgInfo).array());
				}

				return new ServiceResult(ReturnCode.DataVoid, (byte) id);
			}
		}
		return ServiceResult.error(ReturnCode.InvalidCommand);
	}

	void factoryReset() {
		resetToolAccessSequence();
		clearFailureLog();
	}

	private void initFailureCounter(final int errorType, final int value) {
		securityFailure(errorType, __ -> value, null, null, 0, 0);
	}

	private byte[] failureCountersArray() {
		final int scf = failureCounter(InvalidScf);
		final int seqno = failureCounter(SeqNoError);
		final int crypto = failureCounter(CryptoError);
		final int role = failureCounter(AccessAndRoleError);
		return ByteBuffer.allocate(8).putShort((short) scf).putShort((short) seqno).putShort((short) crypto)
				.putShort((short) role).array();
	}

	private void clearFailureLog() {
		initFailureCounter(InvalidScf, 0);
		initFailureCounter(SeqNoError, 0);
		initFailureCounter(CryptoError, 0);
		initFailureCounter(AccessAndRoleError, 0);
		lastFailures.clear();
	}

	private void resetToolAccessSequence() {
		final int pidDownloadCounter = 30;
		long counter = 0;
		try {
			counter = unsigned(device.getInterfaceObjectServer().getProperty(0, pidDownloadCounter, 1, 1));
		}
		catch (final KnxPropertyException ignore) {}
		// always reset seq to > 1, to avoid triggering sync.req during securing data
		final long initial = counter * 20 + ThreadLocalRandom.current().nextInt(20) + 2;
		updateSequenceNumber(true, initial);
	}

	private void addSecureLink(final IndividualAddress address, final long lastValidSeqNo) {
		final byte[] addresses = securityInterface.get(Pid.SecurityIndividualAddressTable);
		final int raw = address.getRawAddress();
		final int entrySize = 2 + SeqSize;
		final int idx = binarySearch(addresses, entrySize, 0, 2, raw);

		final int insert = idx < 0 ? -idx : idx + 1;
		final var element = ByteBuffer.allocate(entrySize).putShort((short) raw).put(sixBytes(lastValidSeqNo)).array();
		securityInterface.set(Pid.SecurityIndividualAddressTable, insert, 1, element);
	}

	private void tryAddSecuredGroupAddress(final GroupAddress address, final byte[] groupKey) {
		try {
			addSecuredGroupAddress(address, groupKey);
		}
		catch (final KnxSecureException e) {}
	}

	private void addSecuredGroupAddress(final GroupAddress address, final byte[] groupKey) {
		if (groupKey.length != 0 && groupKey.length != 16)
			throw new KNXIllegalArgumentException("group key with invalid length " + groupKey.length);

		final int gaIndex = groupAddressIndex(address)
				.orElseThrow(() -> new KnxSecureException(address + " not in address table"));

		final byte[] addresses = securityInterface.get(Pid.GroupKeyTable);
		final int entrySize = 2 + KeySize;
		final int idx = binarySearch(addresses, entrySize, 0, 2, gaIndex);

		final int insert = idx < 0 ? -idx : idx + 1;
		final var element = ByteBuffer.allocate(entrySize).putShort((short) gaIndex).put(groupKey).array();
		securityInterface.set(Pid.GroupKeyTable, insert, 1, element);
	}

	// returns 1-based index of address in security IA table
	private int indAddressIndex(final IndividualAddress address) {
		final byte[] addresses = securityInterface.get(Pid.SecurityIndividualAddressTable);
		final int entrySize = 2 + SeqSize;
		return 1 + binarySearch(addresses, entrySize, 0, 2, address.getRawAddress());
	}

	// returns 1-based index of address in group address table
	private Optional<Integer> groupAddressIndex(final GroupAddress address) {
		return KnxDeviceServiceLogic.groupAddressIndex(device.getInterfaceObjectServer(), address);
	}

	// returns 1-based index of address in group address table
	private Optional<Integer> groupObjectIndex(final int groupAddressIndex) {
		return KnxDeviceServiceLogic.groupObjectIndex(device.getInterfaceObjectServer(), groupAddressIndex);
	}

	// returns p2p key for IA index
	private byte[] p2pKey(final int addressIndex) {
		return lookupKey(Pid.P2PKeyTable, addressIndex, 2 + KeySize + 2);
	}

	// returns group key for group address index
	private byte[] groupKey(final int addressIndex) {
		return lookupKey(Pid.GroupKeyTable, addressIndex, 2 + KeySize);
	}

	private byte[] lookupKey(final int pidTable, final int addressIndex, final int entrySize) {
		if (!securityInterface.isLoaded())
			return null;

		final byte[] keyArray = securityInterface.get(pidTable);
		final int idx = binarySearch(keyArray, entrySize, 0, 2, addressIndex);
		if (idx < 0)
			return null;
		final int offset = idx * entrySize + 2;
		return Arrays.copyOfRange(keyArray, offset, offset + KeySize);
	}

	private int groupObjectSecurity(final int groupObjectIndex) {
		return securityInterface.get(Pid.GOSecurityFlags, groupObjectIndex, 1)[0] & 0xff;
	}

	static int binarySearch(final byte[] a, final int entrySize, final int valueOffset, final int typeSize,
			final long key) {
		assert entrySize >= valueOffset + typeSize;
		assert a.length % entrySize == 0;

		int low = 0;
		int high = a.length / entrySize - 1;

		while (low <= high) {
			final int mid = (low + high) >>> 1;
			final int from = mid * entrySize + valueOffset;
			final byte[] midVal = Arrays.copyOfRange(a, from, from + typeSize);
			final long u = unsigned(midVal);
			final long cmp = u - key;
			if (cmp < 0)
				low = mid + 1;
			else if (cmp > 0)
				high = mid - 1;
			else
				return mid;
		}
		return -(low + 1);
	}

	private static long unsigned(final byte[] data) {
		long l = 0;
		for (final byte b : data)
			l = (l << 8) + (b & 0xff);
		return l;
	}

	private static ByteBuffer sixBytes(final long num) {
		return ByteBuffer.allocate(6).putShort((short) (num >> 32)).putInt((int) num).flip();
	}
}

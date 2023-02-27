/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2023 B. Malinowsky

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

import static io.calimero.DataUnitBuilder.decodeAPCI;
import static io.calimero.DataUnitBuilder.toHex;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.EventObject;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;

import io.calimero.CloseEvent;
import io.calimero.DataUnitBuilder;
import io.calimero.DetachEvent;
import io.calimero.DeviceDescriptor;
import io.calimero.FrameEvent;
import io.calimero.GroupAddress;
import io.calimero.IndividualAddress;
import io.calimero.KNXAddress;
import io.calimero.KNXIllegalArgumentException;
import io.calimero.KNXTimeoutException;
import io.calimero.KnxRuntimeException;
import io.calimero.Priority;
import io.calimero.ReturnCode;
import io.calimero.SerialNumber;
import io.calimero.cemi.CEMI;
import io.calimero.cemi.CEMILData;
import io.calimero.cemi.CemiTData;
import io.calimero.device.ios.DeviceObject;
import io.calimero.device.ios.InterfaceObject;
import io.calimero.device.ios.InterfaceObjectServer;
import io.calimero.device.ios.KnxPropertyException;
import io.calimero.device.ios.SecurityObject;
import io.calimero.dptxlator.PropertyTypes;
import io.calimero.knxnetip.util.ServiceFamiliesDIB.ServiceFamily;
import io.calimero.link.KNXLinkClosedException;
import io.calimero.link.medium.KNXMediumSettings;
import io.calimero.link.medium.PLSettings;
import io.calimero.link.medium.RFSettings;
import io.calimero.mgmt.Description;
import io.calimero.mgmt.Destination;
import io.calimero.mgmt.Destination.AggregatorProxy;
import io.calimero.mgmt.Destination.State;
import io.calimero.mgmt.KNXDisconnectException;
import io.calimero.mgmt.ManagementClient.EraseCode;
import io.calimero.mgmt.PropertyAccess;
import io.calimero.mgmt.PropertyAccess.PID;
import io.calimero.mgmt.PropertyClient;
import io.calimero.mgmt.PropertyClient.PropertyKey;
import io.calimero.mgmt.TransportLayer;
import io.calimero.mgmt.TransportListener;
import io.calimero.secure.SecurityControl;
import io.calimero.secure.SecurityControl.DataSecurity;

/**
 * Listens to TL notifications, dispatches them to the appropriate management services, and answers back to the sender
 * using the service results.
 *
 * @author B. Malinowsky
 */
class ManagementServiceNotifier implements TransportListener, AutoCloseable
{
	// service IDs copied over from management client
	private static final int ADC_READ = 0x0180;
	private static final int ADC_RESPONSE = 0x01C0;

	private static final int AUTHORIZE_READ = 0x03D1;
	private static final int AUTHORIZE_RESPONSE = 0x03D2;

	private static final int DOA_WRITE = 0x3E0;
	private static final int DOA_READ = 0x3E1;
	private static final int DOA_RESPONSE = 0x3E2;
	private static final int DOA_SELECTIVE_READ = 0x3E3;

	private static final int DoASerialNumberRead = 0b1111101100;
	private static final int DoASerialNumberResponse = 0b1111101101;
	private static final int DoASerialNumberWrite = 0b1111101110;

	private static final int IND_ADDR_READ = 0x0100;
	private static final int IND_ADDR_RESPONSE = 0x0140;
	private static final int IND_ADDR_WRITE = 0xC0;

	private static final int IND_ADDR_SN_READ = 0x03DC;
	private static final int IND_ADDR_SN_RESPONSE = 0x03DD;
	private static final int IND_ADDR_SN_WRITE = 0x03DE;

	private static final int DEVICE_DESC_READ = 0x300;
	private static final int DEVICE_DESC_RESPONSE = 0x340;

	private static final int KEY_WRITE = 0x03D3;
	private static final int KEY_RESPONSE = 0x03D4;

	private static final int MEMORY_READ = 0x0200;
	private static final int MEMORY_RESPONSE = 0x0240;
	private static final int MEMORY_WRITE = 0x0280;

	private static final int PROPERTY_DESC_READ = 0x03D8;
	private static final int PROPERTY_DESC_RESPONSE = 0x03D9;

	private static final int PROPERTY_READ = 0x03D5;
	private static final int PROPERTY_RESPONSE = 0x03D6;
	private static final int PROPERTY_WRITE = 0x03D7;

	private static final int RESTART = 0x0380;

	static final int FunctionPropertyCommand = 0b1011000111;
	private static final int FunctionPropertyStateRead = 0b1011001000;
	private static final int FunctionPropertyStateResponse = 0b1011001001;

	static final int MemoryExtendedWrite = 0b0111111011;
	private static final int MemoryExtendedWriteResponse = 0b0111111100;
	static final int MemoryExtendedRead = 0b0111111101;
	private static final int MemoryExtendedReadResponse = 0b0111111110;

	private static final int SystemNetworkParamRead = 0b0111001000;
	private static final int SystemNetworkParamResponse = 0b0111001001;
	private static final int SystemNetworkParamWrite = 0b0111001010;

	private static final int NetworkParamRead = 0b1111011010;
	private static final int NetworkParamResponse = 0b1111011011;
	private static final int NetworkParamWrite = 0b1111100100;

	private static final int PropertyExtRead = 0b0111001100;
	private static final int PropertyExtResponse = 0b0111001101;
	private static final int PropertyExtWriteCon = 0b0111001110;
	private static final int PropertyExtWriteConResponse = 0b0111001111;
	private static final int PropertyExtWriteUnCon = 0b0111010000;
	private static final int PropertyExtDescriptionRead = 0b0111010010;
	private static final int PropertyExtDescriptionResponse = 0b0111010011;

	private static final int FunctionPropertyExtCommand =       0b0111010100;
	private static final int FunctionPropertyExtStateRead =     0b0111010101;
	private static final int FunctionPropertyExtStateResponse = 0b0111010110;


	private static final int defaultMaxApduLength = 254;
	private boolean missingApduLength;

	private final BaseKnxDevice device;
	private final TransportLayer tl;
	private final DeviceSecureApplicationLayer sal;
	private final ManagementService mgmtSvc;

	private final Logger logger;

	private final int lengthDoA;

	private SecurityControl securityCtrl;

	// pre-condition: device != null, link != null
	ManagementServiceNotifier(final BaseKnxDevice device, final ManagementService mgmt) {
		this.device = device;
		tl = device.transportLayer();
		sal = (DeviceSecureApplicationLayer) device.secureApplicationLayer();
		mgmtSvc = mgmt;
		logger = device.logger();

		final int medium = device.getDeviceLink().getKNXMedium().getMedium();
		if (medium == KNXMediumSettings.MEDIUM_PL110)
			lengthDoA = 2;
		else if (medium == KNXMediumSettings.MEDIUM_RF)
			lengthDoA = 6;
		else if (medium == KNXMediumSettings.MEDIUM_KNXIP)
			lengthDoA = 4;
		else
			lengthDoA = 0;

		sal.addListener(this);
		AccessPolicies.definitions = device.getInterfaceObjectServer().propertyDefinitions();
	}

	@Override
	public void broadcast(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	@Override
	public void dataConnected(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	@Override
	public void dataIndividual(final FrameEvent e)
	{
		dispatchAndRespond(e);
	}

	@Override
	public void disconnected(final Destination d)
	{
		d.destroy();
		((KnxDeviceServiceLogic) mgmtSvc).destinationDisconnected(d);
	}

	@Override
	public void group(final FrameEvent e)
	{}

	@Override
	public void detached(final DetachEvent e)
	{}

	@Override
	public void linkClosed(final CloseEvent e)
	{
		logger.info("attached link was closed");
	}

	private volatile Priority svcPriority;

	public void respond(final EventObject e, final ServiceResult<?>sr)
	{
		// since our service code is not split up in request/response, just do everything here
		final FrameEvent fe = (FrameEvent) e;
		final CEMI cemi = fe.getFrame();

		final IndividualAddress sender;
		final KNXAddress dst;
		final Destination d;
		final byte[] tpdu = cemi.getPayload();

		if (cemi instanceof CemiTData) {
			sender = new IndividualAddress(0);
			dst = new IndividualAddress(0);
			d = tl.createDestination(sender, false);
			d.close();
		}
		else {
			final CEMILData ldata = (CEMILData) cemi;
			sender = ldata.getSource();
			// TODO actually this check is for CL mode and should be made in transport layer
			d = tl.destination(sender).orElseGet(() -> tl.createDestination(sender, false));

			dst = ldata.getDestination();
			svcPriority = ldata.getPriority();
		}

		final int svc = DataUnitBuilder.getAPDUService(tpdu);
		final byte[] asdu = DataUnitBuilder.extractASDU(tpdu);

		if (tpdu.length - 1 > getMaxApduLength()) {
			logger.warn("discard {}->{} {}: exceeds max. allowed APDU length of {}", sender, dst,
					DataUnitBuilder.decode(tpdu, dst), getMaxApduLength());
			return;
		}

		try {
			dispatchToService(svc, asdu, dst, d, fe.security().orElse(SecurityControl.Plain));
		}
		catch (final RuntimeException rte) {
			logger.warn("failed to execute service {}->{} {}: {}", sender, dst, DataUnitBuilder.decode(tpdu, dst),
					toHex(asdu, " "), rte);
		}
	}

	@Override
	public void close()
	{
		tl.detach();
	}

	private void dispatchAndRespond(final FrameEvent e)
	{
		final var cemi = e.getFrame();
		if (cemi instanceof CEMILData) {
			final CEMILData ldata = (CEMILData) cemi;
			final var dst = ldata.getDestination();
			if (dst instanceof IndividualAddress && !dst.equals(device.getAddress()))
				return;
		}
		// we do everything in respond
		device.dispatch(e, ServiceResult::empty, this::respond);
	}

	private void dispatchToService(final int svc, final byte[] data, final KNXAddress dst, final Destination respondTo,
			final SecurityControl secCtrl) {
		final boolean granted = AccessPolicies.checkServiceAccess(svc, sal.isSecurityModeEnabled(), secCtrl);
		if (!granted)
			return;

		securityCtrl = secCtrl;
		final String name = decodeAPCI(svc);
		if (svc == MEMORY_READ)
			onMemoryRead(name, respondTo, data);
		else if (svc == MEMORY_WRITE)
			onMemoryWrite(name, respondTo, data);
		else if (svc == PROPERTY_DESC_READ)
			onPropDescRead(name, dst, respondTo, data);
		else if (svc == PROPERTY_READ)
			onPropertyRead(name, dst, respondTo, data);
		else if (svc == PROPERTY_WRITE)
			onPropertyWrite(name, dst, respondTo, data);
		else if (svc == DEVICE_DESC_READ)
			onDeviceDescRead(name, respondTo, data);
		else if (svc == ADC_READ)
			onAdcRead(name, respondTo, data);
		else if (svc == AUTHORIZE_READ)
			onAuthorize(name, respondTo, data);
		else if (svc == IND_ADDR_READ)
			onIndAddrRead(name, respondTo, data);
		else if (svc == IND_ADDR_WRITE)
			onIndAddrWrite(name, respondTo, data);
		else if (svc == IND_ADDR_SN_READ)
			onIndAddrSnRead(name, respondTo, data);
		else if (svc == IND_ADDR_SN_WRITE)
			onIndAddrSnWrite(name, respondTo, data);
		else if (svc == DOA_READ)
			onDoARead(name, respondTo, data);
		else if (svc == DOA_SELECTIVE_READ)
			onDoASelectiveRead(name, respondTo, data);
		else if (svc == DOA_WRITE)
			onDoAWrite(name, respondTo, data);
		else if (svc == DoASerialNumberRead)
			onDoASerialNumberRead(name, respondTo, data);
		else if (svc == DoASerialNumberWrite)
			onDoASerialNumberWrite(name, respondTo, data);
		else if (svc == KEY_WRITE)
			onKeyWrite(name, respondTo, data);
		else if (svc == RESTART)
			onRestart(name, respondTo, data);
		else if (svc == FunctionPropertyCommand)
			onFunctionPropertyCommandOrState(name, dst, respondTo, true, data);
		else if (svc == FunctionPropertyStateRead)
			onFunctionPropertyCommandOrState(name, dst, respondTo, false, data);
		else if (svc == MemoryExtendedWrite)
			onMemoryExtendedWrite(name, respondTo, data);
		else if (svc == MemoryExtendedRead)
			onMemoryExtendedRead(name, respondTo, data);
		else if (svc == NetworkParamRead)
			onNetworkParamRead(name, respondTo, data, false, dst.getRawAddress() == 0);
		else if (svc == NetworkParamWrite)
			onNetworkParamWrite(name, respondTo, data, false);
		else if (svc == SystemNetworkParamRead)
			onNetworkParamRead(name, respondTo, data, true, dst.getRawAddress() == 0);
		else if (svc == SystemNetworkParamWrite)
			onNetworkParamWrite(name, respondTo, data, true);
		else if (svc == PropertyExtRead)
			onPropertyExtRead(name, dst, respondTo, data);
		else if (svc == PropertyExtWriteCon || svc == PropertyExtWriteUnCon)
			onPropertyExtWrite(name, dst, respondTo, data, svc == PropertyExtWriteCon);
		else if (svc == PropertyExtDescriptionRead)
			onPropertyExtDescriptionRead(name, dst, respondTo, data);
		else if (svc == FunctionPropertyExtCommand)
			onFunctionPropertyExtCommandOrState(name, dst, respondTo, true, data, true);
		else if (svc == FunctionPropertyExtStateRead)
			onFunctionPropertyExtCommandOrState(name, dst, respondTo, false, data, true);
		else
			onManagement(svc, data, dst, respondTo);
	}

	// test-info length of network param services is impl-specific, we allow operand (1 byte) + mfr-code (2 bytes)
	private static final int testInfoLength = 3;

	private void onNetworkParamRead(final String name, final Destination respondTo, final byte[] data,
			final boolean systemRead, final boolean broadcast) {
		final var paramTypeSize = systemRead ? 4 : 3;
		if (!verifyLength(data.length, paramTypeSize + 1, paramTypeSize + testInfoLength, name))
			return;
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		var objectType = buffer.getShort() & 0xff;
		var pid = systemRead ? (buffer.getShort() & 0xffff) >> 4 : buffer.get() & 0xff;
		var info = new byte[buffer.remaining()];
		buffer.get(info);

		final String propertyName = propertyNameByObjectType(objectType, pid);
		logger.trace("{}->{} {} {}(1)|{}{} info {}", respondTo.getAddress(), GroupAddress.Broadcast, name,
				objectType, pid, propertyName, toHex(info, " "));

		final ServiceResult<byte[]> sr = mgmtSvc.readParameter(objectType, pid, info);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] res = sr.result();
		if (res.length == 0) {
			// no negative response for network-param read service in (system) broadcast communication mode
			if (broadcast)
				return;
			objectType = 0xffff;
			pid = 0xff;
			info = new byte[0];
		}

		final ByteBuffer asdu = ByteBuffer.allocate(paramTypeSize + info.length + res.length);
		asdu.putShort((short) objectType);
		if (systemRead)
			asdu.putShort((short) (pid << 4));
		else
			asdu.put((byte) pid);
		asdu.put(info).put(res);

		final var service = systemRead ? SystemNetworkParamResponse : NetworkParamResponse;
		if (broadcast) {
			// NYI wait random time
			final var apdu = DataUnitBuilder.createAPDU(service, asdu.array());
			sendBroadcast(systemRead, apdu, Priority.SYSTEM, decodeAPCI(service));
		}
		else
			send(respondTo, service, asdu.array(), Priority.SYSTEM);
	}

	private void onNetworkParamWrite(final String name, final Destination respondTo, final byte[] data,
			final boolean systemWrite) {
		final var minExpected = systemWrite ? 5 : 4;
		if (!verifyLength(data.length, minExpected, 12, name))
			return;
		final ByteBuffer buffer = ByteBuffer.wrap(data);
		final var objectType = buffer.getShort() & 0xff;
		final var pid = systemWrite ? (buffer.getShort() & 0xffff) >> 4 : buffer.get() & 0xff;
		final var info = new byte[buffer.remaining()];
		buffer.get(info);
		logger.trace("{}->{} {} {}(1)|{}{} info {}", respondTo.getAddress(), "[]", name,
				objectType, pid, propertyNameByObjectType(objectType, pid), toHex(info, " "));

		mgmtSvc.writeParameter(objectType, pid, info);
	}

	private void onRestart(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 3, name))
			return;

		// bits 1 to 4 in frame byte 7 (first byte ASDU) shall be 0; if not,
		// we have to ignore the service without any response
		final int reserved = data[0] & 0x1e;
		if (reserved != 0) {
			logger.warn("{} uses reserved bits -- ignore", name);
			return;
		}

		final boolean masterReset = (data[0] & 0x01) == 1;
		final int eraseCode = masterReset ? data[1] & 0xff : 0;
		final int channel = masterReset ? data[2] & 0xff : 0;

		final int unsupportedEraseCode = 2;
		byte errorCode = unsupportedEraseCode;
		ServiceResult<Duration> sr = ServiceResult.of(Duration.ZERO);

		EraseCode code = null;
		try {
			if (eraseCode > 0)
				code = EraseCode.of(eraseCode);
			if (!AccessPolicies.checkRestartAccess(masterReset, code, sal.isSecurityModeEnabled(), securityCtrl))
				return;
			logger.trace("{}->{} {}: {}, channel {}", respondTo.getAddress(), device.getAddress(), name,
					code == null ? "Basic Restart" : code, channel);

			// a basic restart does not have any response,
			// a master reset returns an error code and process time
			sr = mgmtSvc.restart(masterReset, code, channel);
			if (!masterReset || ignoreOrSchedule(sr))
				return;
			errorCode = 0;
		}
		catch (final KNXIllegalArgumentException e) {
			// unsupported erase code
			logger.warn("{}->{} {}: {}", respondTo.getAddress(), device.getAddress(), name, e.getMessage());
		}


		final byte[] asdu = new byte[4];
		asdu[0] = (1 << 5) | 1; // set response bit and master reset bit
		asdu[1] = errorCode;
		asdu[2] = 0;
		asdu[3] = (byte) sr.result().toSeconds();
		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(RESTART, asdu);
		send(respondTo, apdu, sr.getPriority(), name);

		final var destinations = transportLayerProxies().values().stream().map(p -> p.getDestination())
				.collect(Collectors.toList());
		destinations.forEach(Destination::destroy);

		if (code == EraseCode.FactoryReset || code == EraseCode.FactoryResetWithoutIndividualAddress) {
			SecurityObject.lookup(device.getInterfaceObjectServer()).populateWithDefaults();
		}
	}

	// p2p connection-oriented mode
	private void onKeyWrite(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 5, 5, name))
			return;
		if (!respondTo.isConnectionOriented())
			return;
		final int level = data[0] & 0xff;
		final byte[] key = Arrays.copyOfRange(data, 1, 5);
		logger.trace("{}->{} {} level {} key 0x{}", respondTo.getAddress(), device.getAddress(), name, level, toHex(key, ""));

		final ServiceResult<Integer> sr = mgmtSvc.writeAuthKey(respondTo, level, key);
		if (ignoreOrSchedule(sr))
			return;

		// result is one byte containing the set level
		send(respondTo, KEY_RESPONSE, new byte[] { (byte) (int) sr.result() }, sr.getPriority());
	}

	private void onIndAddrSnWrite(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 12, 12, name))
			return;
		final var sn = SerialNumber.from(Arrays.copyOfRange(data, 0, 6));
		final byte[] addr = Arrays.copyOfRange(data, 6, 8);
		final byte[] reserved = Arrays.copyOfRange(data, 8, 12);

		final IndividualAddress ia = new IndividualAddress(addr);
		logger.trace("{}->{} {} {} {}", respondTo.getAddress(), device.getAddress(), name, sn, ia);
		// safety check that reserved area is zeroed out
		// we don't bail, since it's not required by the spec
		for (int i = 0; i < reserved.length; i++) {
			final byte b = reserved[i];
			if (b != 0) {
				logger.warn("byte " + (16 + i) + " not 0 (reserved area)");
			}
		}
		mgmtSvc.writeAddressSerial(sn, ia);
	}

	private void onIndAddrSnRead(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 6, 6, name))
			return;

		final var sn = SerialNumber.from(data);
		logger.trace("{}->{} {} {}", respondTo.getAddress(), device.getAddress(), name, sn);
		final ServiceResult<Boolean> sr = mgmtSvc.readAddressSerial(sn);
		if (!sr.result())
			return;
		if (ignoreOrSchedule(sr))
			return;

		// [serial no, DOA, 2 bytes reserved]
		final byte[] asdu = new byte[6 + 2 + 2];
		for (int i = 0; i < data.length; i++) {
			final byte b = data[i];
			asdu[i] = b;
		}
		final byte[] apdu = DataUnitBuilder.createAPDU(IND_ADDR_SN_RESPONSE, asdu);
		// priority is always system
		sendBroadcast(false, apdu, Priority.SYSTEM, decodeAPCI(IND_ADDR_SN_RESPONSE));
	}

	private void onIndAddrWrite(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 2, 2, name))
			return;

		final byte[] addr = Arrays.copyOfRange(data, 0, 2);
		final IndividualAddress ia = new IndividualAddress(addr);
		logger.trace("{}->{} {} {}", respondTo.getAddress(), device.getAddress(), name, ia);

		// a device shall only set its address if in programming mode
		mgmtSvc.writeAddress(ia);
	}

	private void onIndAddrRead(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 1, name))
			return;

		logger.trace("{}->{} {}", respondTo.getAddress(), device.getAddress(), name);
		// only a device in programming mode shall respond to this service
		final ServiceResult<Boolean> sr = mgmtSvc.readAddress();
		if (!sr.result())
			return;
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = new byte[0];
		final byte[] apdu = DataUnitBuilder.createAPDU(IND_ADDR_RESPONSE, asdu);
		sendBroadcast(false, apdu, Priority.SYSTEM, decodeAPCI(IND_ADDR_RESPONSE));
	}

	private void onDoARead(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 0, 0, name))
			return;

		logger.trace("{}->{} {}", respondTo.getAddress(), device.getAddress(), name);
		final ServiceResult<Boolean> sr = mgmtSvc.readDomainAddress();
		sendDoAresponse(respondTo, sr);
	}

	private void onDoASelectiveRead(final String name, final Destination respondTo, final byte[] data)
	{
		// selective read service: 5 bytes with PL DoA (length 2 bytes), 14 bytes with RF DoA (length 6 bytes)
		if (!verifyLength(data.length, 5, 14, name))
			return;
		if (data[0] == 0 && data.length == 5) {
			// Type 0 - two byte DoA
			final byte[] domain = Arrays.copyOfRange(data, 0, 2);
			final IndividualAddress ia = new IndividualAddress(Arrays.copyOfRange(data, 2, 4));
			final int range = data[4] & 0xff;
			logger.trace("{}->{} {} {} - {}", respondTo.getAddress(), device.getAddress(), name, ia,
					new IndividualAddress(ia.getRawAddress() + range));
			final ServiceResult<Boolean> sr = mgmtSvc.readDomainAddress(domain, ia, range);
			sendDoAresponse(respondTo, sr);
		}
		else if (data[0] == 1 && data.length == 14) {
			// Type 1 - six byte DoA
			final byte[] start = Arrays.copyOfRange(data, 1, 1 + 6);
			final byte[] end = Arrays.copyOfRange(data, 1 + 6, 1 + 6 + 6);
			logger.trace("{}->{} {} {} - {}", respondTo.getAddress(), device.getAddress(), name, toHex(start, ""),
					toHex(end, ""));
			final ServiceResult<Boolean> sr = mgmtSvc.readDomainAddress(start, end);
			sendDoAresponse(respondTo, sr);
		}
	}

	private void sendDoAresponse(final Destination respondTo, final ServiceResult<Boolean> sr)
	{
		if (!sr.result())
			return;
		if (ignoreOrSchedule(sr))
			return;
		final byte[] domain = domainAddress();
		if (domain.length != lengthDoA) {
			logger.error("length of domain address is {} bytes, should be {} - ignore", domain.length, lengthDoA);
			return;
		}
		final byte[] asdu;
		if (lengthDoA == 2)
			asdu = domain;
		else if (lengthDoA == 6)
			asdu = new byte[] { 1, domain[0], domain[1], domain[2], domain[3], domain[4], domain[5] };
		else
			return;
		send(respondTo, DOA_RESPONSE, asdu, sr.getPriority());
	}

	private byte[] domainAddress() {
		final var settings = device.getDeviceLink().getKNXMedium();
		final byte[] domain = settings instanceof PLSettings ? ((PLSettings) settings).getDomainAddress()
				: settings instanceof RFSettings ? ((RFSettings) settings).getDomainAddress() : new byte[0];
		return domain;
	}

	private void onDoAWrite(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, lengthDoA, lengthDoA, name))
			return;
		final byte[] domain = Arrays.copyOfRange(data, 0, lengthDoA);
		logger.trace("{}->{} {} 0x{}", respondTo.getAddress(), device.getAddress(), name, toHex(domain, ""));
		mgmtSvc.writeDomainAddress(domain);
	}

	private void onDoASerialNumberWrite(final String name, final Destination respondTo, final byte[] data) {
		final int maxLength = lengthDoA == 4 ? 21 : lengthDoA;
		if (!verifyLength(data.length, SerialNumber.Size + lengthDoA, SerialNumber.Size + maxLength, name))
			return;
		final var sno = SerialNumber.from(Arrays.copyOfRange(data, 0, SerialNumber.Size));
		if (!matchesOurSerialNumber(sno))
			return;

		final byte[] domain = Arrays.copyOfRange(data, SerialNumber.Size, data.length);
		boolean disableSecureRouting = false;
		boolean enableSecureRouting = false;
		if (lengthDoA == 4) {
			if (securityCtrl.systemBroadcast() && securityCtrl.security() == DataSecurity.AuthConf
					&& (domain.length == 4 || domain.length == 21)) {
				if (domain.length == 4)
					disableSecureRouting = true;
				if (domain.length == 21) {
					enableSecureRouting = true;

					final int routingSecurityVersion = domain[5] & 0xff;
					if (routingSecurityVersion != 1)
						return;
				}
			}
			else if (domain.length != 4 || sal.isSecurityModeEnabled())
				return;
		}

		logger.trace("{}->{} {} SN {} DoA 0x{}", respondTo.getAddress(), device.getAddress(), name, sno, toHex(domain, ""));
		mgmtSvc.writeDomainAddress(domain);

		if (lengthDoA == 4) {
			Arrays.fill(domain, (byte) 0);

			final int pidSecuredServices = 94;
			final var ios = device.getInterfaceObjectServer();
			final int routingBit = 1 << ServiceFamily.Routing.id();

			// if DoA of length 4 and A+C, then routing security version in PID_SECURED_SERVICES shall be set 0, and
			// no further send/rcv of encrypted routing frames
			if (disableSecureRouting) {
				try {
					final byte[] securedFamilies = ios.getProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
							pidSecuredServices, 1, 1);
					securedFamilies[1] &= ~routingBit;
					ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1, pidSecuredServices, 1, 1,
							securedFamilies);
				}
				catch (final KnxPropertyException e) {
					// ignore non-existing property
				}
			}
			// if DoA of length 21 and A+C, then routing security version in PID_SECURED_SERVICES shall be set, and
			// device security mode enabled
			if (enableSecureRouting) {
				final byte[] securedFamilies = ios.getProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1,
						pidSecuredServices, 1, 1);
				securedFamilies[1] |= routingBit;
				ios.setProperty(InterfaceObject.KNXNETIP_PARAMETER_OBJECT, 1, pidSecuredServices, 1, 1,
						securedFamilies);

				sal.setSecurityMode(true);
			}
		}
	}

	private void onDoASerialNumberRead(final String name, final Destination respondTo, final byte[] data) {
		if (!verifyLength(data.length, SerialNumber.Size, SerialNumber.Size, name))
			return;
		final var sno = SerialNumber.from(data);
		if (!matchesOurSerialNumber(sno))
			return;

		logger.trace("{}->{} {} SN {}", respondTo.getAddress(), device.getAddress(), name, sno);
		final var endDoA = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
		final var sr = mgmtSvc.readDomainAddress(new byte[lengthDoA], Arrays.copyOfRange(endDoA, 0, lengthDoA));
		if (!sr.result())
			return;
		if (ignoreOrSchedule(sr))
			return;

		final byte[] domain = domainAddress();
		if (domain.length != lengthDoA) {
			logger.warn("length of domain address is {} bytes, should be {} - ignore", domain.length, lengthDoA);
			return;
		}

		final byte[] asdu = ByteBuffer.allocate(SerialNumber.Size + lengthDoA).put(sno.array()).put(domain).array();
		final var apdu = DataUnitBuilder.createAPDU(DoASerialNumberResponse, asdu);
		sendBroadcast(true, apdu, Priority.SYSTEM, decodeAPCI(DoASerialNumberResponse));
	}

	private boolean matchesOurSerialNumber(final SerialNumber sno) {
		var serialNumber = SerialNumber.Zero;
		try {
			serialNumber = DeviceObject.lookup(device.getInterfaceObjectServer()).serialNumber();
		}
		catch (final KnxPropertyException e) {}

		final var medium = device.getDeviceLink().getKNXMedium();
		if (serialNumber.equals(SerialNumber.Zero) && medium instanceof RFSettings) {
			final var rfSettings = (RFSettings) medium;
			serialNumber = rfSettings.serialNumber();
			if (serialNumber.equals(SerialNumber.Zero)) {
				logger.warn("RF device with no serial number");
			}
		}
		return sno.equals(serialNumber);
	}

	// p2p connection-oriented mode
	private void onAuthorize(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 5, 5, name))
			return;
		if (respondTo.getState() != Destination.State.OpenIdle)
			return;

		final int reserved = data[0] & 0xff;
		if (reserved != 0) {
			logger.warn("first byte in authorize request not zero, ignore");
			return;
		}
		final byte[] key = Arrays.copyOfRange(data, 1, 5);
		logger.trace("{}->{} {} key 0x{}", respondTo.getAddress(), device.getAddress(), name, toHex(key, ""));
		final ServiceResult<Integer> sr = mgmtSvc.authorize(respondTo, key);
		if (ignoreOrSchedule(sr))
			return;

		send(respondTo, AUTHORIZE_RESPONSE, new byte[] { (byte) (int) sr.result() }, sr.getPriority());
	}

	// p2p connection-oriented mode
	private void onAdcRead(final String name, final Destination respondTo, final byte[] data)
	{
		if (!verifyLength(data.length, 2, 2, name))
			return;
		final int channel = data[0] & 0x3f;
		// number of consecutive reads of AD converter
		int reads = data[1] & 0xff;
		logger.trace("{}->{} {} channel {}, read count {}", respondTo.getAddress(), device.getAddress(), name, channel, reads);
		ServiceResult<Integer> sr = ServiceResult.of(0);
		try {
			sr = mgmtSvc.readADC(channel, reads);
			if (ignoreOrSchedule(sr))
				return;
		}
		catch (final KnxRuntimeException e) {
			reads = 0;
		}

		// the returned structure is [channel, read count, value high, value low]
		final byte[] asdu = ByteBuffer.allocate(4).put((byte) channel).put((byte) reads)
				.putShort((short) (int) sr.result()).array();
		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(ADC_RESPONSE, asdu);
		send(respondTo, apdu, sr.getPriority(), decodeAPCI(ADC_RESPONSE));
	}

	private void onDeviceDescRead(final String name, final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 1, 1, name))
			return;
		final int type = data[0] & 0xff;
		// Descriptor type 0:
		// mask type (8 bit): Medium Type (4 bit), Firmware Type (4 bit)
		// firmware version (8 bit): version (4 bit), sub code (4 bit)

		// Descriptor type 1:
		// | application manufacturer (16 bit) | device type (16 bit) | version (8 bit) |
		// link mgmt service support (2 bit) | logical tag (LT) base value (6 bit) |
		// CI 1 (16 bit) | CI 2 (16 bit) | CI 3 (16 bit) | CI 4 (16 bit) |

		logger.trace("{}->{} {} type {}", d.getAddress(), device.getAddress(), name, type);
		if (type != 0 && type != 2) {
			logger.warn("{}: unsupported type {}", name, type);
			return;
		}
		final ServiceResult<DeviceDescriptor> sr = mgmtSvc.readDescriptor(type);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] asdu = sr.result().toByteArray();
		final byte[] apdu = DataUnitBuilder.createAPDU(DEVICE_DESC_RESPONSE, asdu);
		apdu[1] |= type;
		send(d, apdu, svcPriority, decodeAPCI(DEVICE_DESC_RESPONSE));
	}

	private void onPropertyRead(final String name, final KNXAddress dst, final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 4, 4, name))
			return;
		final int objIndex = data[0] & 0xff;
		final int pid = data[1] & 0xff;
		int elements = (data[2] & 0xff) >> 4;
		final int start = (data[2] & 0x0f) << 8 | (data[3] & 0xff);

		logger.trace("{}->{} {} {}|{}{} {}..{}", d.getAddress(), dst, name,
				objIndex, pid, propertyName(objIndex, pid), start, start + elements - 1);


		ServiceResult<byte[]> sr = ServiceResult.empty();
		if (checkPropertyAccess(objIndex, pid, true)) {
			try {
				sr = mgmtSvc.readProperty(d, objIndex, pid, start, elements);
				if (ignoreOrSchedule(sr))
					return;
			}
			catch (KNXIllegalArgumentException | KnxPropertyException e) {
				logger.warn("{}", e.getMessage());
			}
		}

		final byte[] res = sr.result();
		final byte[] asdu = new byte[4 + res.length];
		if (res.length == 0)
			elements = 0;
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) pid;
		asdu[2] = (byte) ((elements << 4) | ((start >>> 8) & 0x0f));
		asdu[3] = (byte) start;
		System.arraycopy(res, 0, asdu, 4, res.length);

		send(d, PROPERTY_RESPONSE, asdu, sr.getPriority());
	}

	private void onPropertyWrite(final String name, final KNXAddress dst, final Destination d, final byte[] data)
	{
		// the max ASDU upper length would be 253 (254 - 1 byte APCI)
		if (!verifyLength(data.length, 5, getMaxApduLength() - 1, name))
			return;
		final int objIndex = data[0] & 0xff;
		final int pid = data[1] & 0xff;
		int elements = (data[2] & 0xff) >> 4;
		final int start = (data[2] & 0x0f) << 8 | (data[3] & 0xff);
		final byte[] propertyData = Arrays.copyOfRange(data, 4, data.length);

		logger.trace("{}->{} {} {}|{}{} {}..{}: {}", d.getAddress(), dst, name,
				objIndex, pid, propertyName(objIndex, pid), start, start + elements - 1, toHex(propertyData, ""));

		ServiceResult<Void> sr = ServiceResult.empty();
		if (checkPropertyAccess(objIndex, pid, true)) {
			try {
				sr = mgmtSvc.writeProperty(d, objIndex, pid, start, elements, propertyData);
				if (ignoreOrSchedule(sr))
					return;
			}
			catch (KNXIllegalArgumentException | KnxPropertyException e) {
				logger.warn("{}->{} {} {}|{}{} {}", d.getAddress(), dst, name, objIndex, pid,
						propertyName(objIndex, pid), e.getMessage());
			}
		}

		// special case of load/run control which uses PDT_CONTROL and returns byte array
		final byte[] res;
		if (pid == PropertyAccess.PID.LOAD_STATE_CONTROL || pid == PropertyAccess.PID.RUN_STATE_CONTROL)
			res = (byte[]) (Object) sr.result();
		else
			res = propertyData;

		int written = res.length;
		if (sr.returnCode() != ReturnCode.Success) {
			elements = 0;
			written = 0;
		}
		final byte[] asdu = new byte[4 + written];
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) pid;
		asdu[2] = (byte) ((elements << 4) | ((start >>> 8) & 0x0f));
		asdu[3] = (byte) start;
		System.arraycopy(res, 0, asdu, 4, written);

		send(d, PROPERTY_RESPONSE, asdu, sr.getPriority());
	}

	private void onPropDescRead(final String name, final KNXAddress dst, final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 3, 3, name))
			return;
		final int objIndex = data[0] & 0xff;
		int pid = data[1] & 0xff;
		final int propIndex = data[2] & 0xff;

		logger.trace("{}->{} {} {}|{} pidx {}{}", d.getAddress(), dst, name,
				objIndex, pid, propIndex, propertyName(objIndex, pid));

		ServiceResult<Description> sr;
		try {
			sr = mgmtSvc.readPropertyDescription(objIndex, pid, propIndex);
		}
		catch (KNXIllegalArgumentException | KnxPropertyException e) {
			logger.warn("{}: {}", name, e.getMessage());

			// answer with non-existent property description on no result
			final byte[] asdu = new byte[7];
			asdu[0] = (byte) objIndex;
			asdu[1] = (byte) pid;
			asdu[2] = (byte) propIndex;
			send(d, PROPERTY_DESC_RESPONSE, asdu, Priority.LOW);
			return;
		}

		if (ignoreOrSchedule(sr))
			return;

		final Description desc = sr.result();
		// read back pid, because it is 0 when the propIndex was used
		pid = desc.getPID();
		final int index = desc.getPropIndex();
		int type = desc.isWriteEnabled() ? 0x80 : 0;
		type |= desc.getPDT();
		final int max = desc.getMaxElements();
		final int access = desc.getReadLevel() << 4 | desc.getWriteLevel();
		final byte[] asdu = new byte[/*7*/] { (byte) objIndex, (byte) pid, (byte) index, (byte) type,
			(byte) (max >>> 8), (byte) max, (byte) access };

		send(d, PROPERTY_DESC_RESPONSE, asdu, sr.getPriority());
	}

	private void onFunctionPropertyCommandOrState(final String name, final KNXAddress dst, final Destination respondTo,
			final boolean isCommand, final byte[] data) {
		if (!verifyLength(data.length, 3, 15, name))
			return;
		final int objIndex = data[0] & 0xff;
		final int pid = data[1] & 0xff;
		final byte[] functionInput = Arrays.copyOfRange(data, 2, data.length);

		logger.trace("{}->{} {} {}|{}{} {}", respondTo.getAddress(), dst, name, objIndex,
				pid, propertyName(objIndex, pid), toHex(functionInput, " "));


		ServiceResult<byte[]> sr = ServiceResult.error(ReturnCode.AccessDenied);
		if (checkPropertyAccess(objIndex, pid, !isCommand)) {
			try {
				final var description = device.getInterfaceObjectServer().getDescription(objIndex, pid);
				if (description.getPDT() == PropertyTypes.PDT_FUNCTION)
					sr = isCommand ? mgmtSvc.functionPropertyCommand(respondTo, objIndex, pid, functionInput)
							: mgmtSvc.readFunctionPropertyState(respondTo, objIndex, pid, functionInput);
				else
					logger.warn("property {}|{} is not a function property", objIndex, pid);

				if (ignoreOrSchedule(sr))
					return;
			}
			catch (KNXIllegalArgumentException | KnxPropertyException e) {
				logger.warn("{}", e.getMessage());
				sr = ServiceResult.error(ReturnCode.AddressVoid);
			}
		}

		// if the property is not a function (PDT_FUNCTION), the response shall not contain a return code and no data
		// in that case, using the Empty result here is fine
		final byte[] res = sr.result();
		final byte[] asdu = new byte[3 + res.length];
		asdu[0] = (byte) objIndex;
		asdu[1] = (byte) pid;
		asdu[2] = (byte) sr.returnCode().code();
		System.arraycopy(res, 0, asdu, 3, res.length);

		send(respondTo, FunctionPropertyStateResponse, asdu, sr.getPriority());
	}

	private void onMemoryWrite(final String name, final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 4, 66, name))
			return;

		// write between 1 and 63 bytes
		int bytes = data[0] & 0xff;
		final int address = ((data[1] & 0xff) << 8) | (data[2] & 0xff);

		// the remote application layer shall ignore a memory-write.ind if
		// the value of the parameter number is greater than maximum APDU length - 3
		if (bytes > getMaxApduLength() - 3) {
			logger.warn("{} of length {} > max. {} bytes - ignore", name, bytes, getMaxApduLength() - 3);
			return;
		}

		final byte[] memory = Arrays.copyOfRange(data, 3, data.length);
		if (memory.length != bytes)
			logger.warn("ill-formed {}: number field = {} but memory length = {}", name, bytes, memory);
		else {
			logger.trace("{}->{} {}: start address 0x{}, {} bytes: {}", d.getAddress(), device.getAddress(), name,
					Integer.toHexString(address), bytes, toHex(memory, " "));
			final ServiceResult<Void> sr = mgmtSvc.writeMemory(address, memory);
			if (ignoreOrSchedule(sr))
				return;
			if (sr.returnCode() != ReturnCode.Success)
				bytes = 0;

			// only respond if verify mode is active
			final boolean verifyByServer = mgmtSvc.isVerifyModeEnabled();
			if (verifyByServer) {
				final byte[] written = memory;
				final byte[] asdu = new byte[3 + bytes];
				asdu[0] = (byte) bytes;
				asdu[1] = (byte) (address >>> 8);
				asdu[2] = (byte) address;
				System.arraycopy(written, 0, asdu, 3, bytes);

				final var apdu = DataUnitBuilder.createLengthOptimizedAPDU(MEMORY_RESPONSE, asdu);
				send(d, apdu, sr.getPriority(), decodeAPCI(MEMORY_RESPONSE));
			}
		}
	}

	private void onMemoryExtendedWrite(final String name, final Destination d, final byte[] data) {
		if (!verifyLength(data.length, 5, 254, name))
			return;

		// write between 1 and 250 bytes
		final int bytes = data[0] & 0xff;
		final int address = ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);

		final ReturnCode rc;
		Priority priority = Priority.LOW;
		if (bytes > getMaxApduLength() - 4) {
			logger.warn("memory-write of length {} > max. {} bytes - ignore", bytes, getMaxApduLength() - 4);
			rc = ReturnCode.ExceedsMaxApduLength;
		}
		else {
			final byte[] memory = Arrays.copyOfRange(data, 4, data.length);
			if (memory.length != bytes) {
				logger.warn("ill-formed memory write: number field = {} but memory length = {}", bytes, memory);
				rc = ReturnCode.Error; // ReturnCode.DataVoid would probably fit better, but is not specified
			}
			else {
				logger.trace("{}->{} {}: start address 0x{}, {} bytes: {}", d.getAddress(), device.getAddress(), name,
						Integer.toHexString(address), bytes, toHex(memory, " "));
				final ServiceResult<Void> sr = mgmtSvc.writeMemory(address, memory);
				if (ignoreOrSchedule(sr))
					return;

				rc = sr.returnCode();
				priority = sr.getPriority();
			}
		}

		final boolean withCrc = rc == ReturnCode.SuccessWithCrc;
		final byte[] asdu = new byte[4 + (withCrc ? 2 : 0)];
		asdu[0] = (byte) rc.code();
		asdu[1] = (byte) (address >>> 16);
		asdu[2] = (byte) (address >>> 8);
		asdu[3] = (byte) address;
		if (withCrc) {
			final int crc = crc16Ccitt(data);
			asdu[4] = (byte) (crc >> 8);
			asdu[5] = (byte) crc;
		}

		send(d, MemoryExtendedWriteResponse, asdu, priority);
	}

	private static int crc16Ccitt(final byte[] input) {
		final int polynom = 0x1021;
		final byte[] padded = Arrays.copyOf(input, input.length + 2);
		int result = 0xffff;
		for (int i = 0; i < 8 * padded.length; i++) {
			result <<= 1;
			final int nextBit = (padded[i / 8] >> (7 - (i % 8))) & 0x1;
			result |= nextBit;
			if ((result & 0x10000) != 0)
				result ^= polynom;
		}
		return result & 0xffff;
	}


	private void onMemoryRead(final String name, final Destination d, final byte[] data)
	{
		if (!verifyLength(data.length, 3, 3, name))
			return;
		final int length = data[0] & 0xff;
		final int address = (data[1] & 0xff) << 8 | (data[2] & 0xff);

		// requests with a length exceeding the maximum APDU size shall be ignored by the application
		if (length > getMaxApduLength() - 3) {
			logger.warn("{} of length {} > max. {} bytes - ignored", name, length, getMaxApduLength() - 3);
			return;
		}
		logger.trace("{}->{} {}: start address 0x{}, {} bytes", d.getAddress(), device.getAddress(), name,
				Integer.toHexString(address), length);
		final ServiceResult<byte[]> sr = mgmtSvc.readMemory(address, length);
		if (ignoreOrSchedule(sr))
			return;

		final byte[] res = sr.result();
		// res null or length 0 indicate memory access problems, i.e.,
		// read protection, invalid address, partial read.
		int bytesRead = length;
		if (res.length != bytesRead)
			bytesRead = 0;

		final byte[] asdu = new byte[3 + bytesRead];
		asdu[0] = (byte) bytesRead;
		asdu[1] = (byte) (address >> 8);
		asdu[2] = (byte) address;
		System.arraycopy(res, 0, asdu, 3, bytesRead);

		final byte[] apdu = DataUnitBuilder.createLengthOptimizedAPDU(MEMORY_RESPONSE, asdu);
		send(d, apdu, sr.getPriority(), decodeAPCI(MEMORY_RESPONSE));
	}

	private void onMemoryExtendedRead(final String name, final Destination d, final byte[] data) {
		if (!verifyLength(data.length, 4, 4, name))
			return;
		final int length = data[0] & 0xff;
		final int address = ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);

		ReturnCode rc;
		byte[] read = {};
		Priority priority = Priority.LOW;
		if (length > getMaxApduLength() - 4) {
			logger.warn("memory-read request of length {} > max. {} bytes - ignored", length, getMaxApduLength() - 4);
			rc = ReturnCode.ExceedsMaxApduLength;
		}
		else {
			logger.trace("{}->{} {}: start address 0x{}, {} bytes", d.getAddress(), device.getAddress(), name,
					Integer.toHexString(address), length);
			final ServiceResult<byte[]> sr = mgmtSvc.readMemory(address, length);

			rc = sr.returnCode();
			final byte[] result = sr.result();
			if (rc == ReturnCode.Success) {
				if (result.length == length)
					read = result;
				else
					rc = ReturnCode.MemoryError;
			}
			priority = sr.getPriority();
		}

		final byte[] asdu = new byte[4 + read.length];
		asdu[0] = (byte) rc.code();
		asdu[1] = (byte) (address >> 16);
		asdu[2] = (byte) (address >> 8);
		asdu[3] = (byte) address;
		System.arraycopy(read, 0, asdu, 4, read.length);
		send(d, MemoryExtendedReadResponse, asdu, priority);
	}

	private void onPropertyExtDescriptionRead(final String name, final KNXAddress dst, final Destination respondTo, final byte[] data) {
		if (!verifyLength(data.length, 7, 7, name))
			return;
		final int iot = (data[0] & 0xff) << 8 | data[1] & 0xff;
		final int instance = (data[2] & 0xff) << 4 | (data[3] & 0xff) >> 4;
		final int pid = (data[3] & 0xf) << 8 | data[4] & 0xff;
		final int pdt = (data[5] & 0xff) >> 4; // reserved, always zero
		if (pdt != 0) {
			logger.warn("{} PDT is reserved, but set to {}, ignore service", name, pdt);
			return;
		}
		final int propIndex = (data[5] & 0xf) << 8 | data[6] & 0xff;

		logger.trace("{}->{} {} {}({})|{} pidx {}{}", respondTo.getAddress(), dst, name, iot,
				instance, pid, propIndex, propertyNameByObjectType(iot, pid));

		ServiceResult<Description> sr;
		try {
			final int objIndex = objectIndex(iot, instance);
			sr = mgmtSvc.readPropertyDescription(objIndex, pid, propIndex);
			if (ignoreOrSchedule(sr))
				return;
		}
		catch (KNXIllegalArgumentException | KnxPropertyException e) {
			logger.warn("read property description: {}", e.getMessage());
			// answer with non-existent property description
			final byte[] asdu = new byte[7];
			asdu[0] = (byte) instance;
			asdu[1] = (byte) pid;
			asdu[2] = (byte) propIndex;
			send(respondTo, PropertyExtDescriptionResponse, asdu, Priority.LOW);
			return;
		}

		final Description desc = sr.result();
		// read back pid, because it is 0 when the propIndex was used
		final int pidResponse = desc.getPID();
		final int index = desc.getPropIndex();
		int type = desc.isWriteEnabled() ? 0x80 : 0;
		type |= desc.getPDT();
		final int max = desc.getMaxElements();
		final int access = desc.getReadLevel() << 4 | desc.getWriteLevel();
		final byte[] asdu = new byte[/*7*/] { (byte) instance, (byte) pidResponse, (byte) index, (byte) type,
			(byte) (max >>> 8), (byte) max, (byte) access };

		send(respondTo, PropertyExtDescriptionResponse, asdu, sr.getPriority());
	}

	private void onPropertyExtRead(final String name, final KNXAddress dst, final Destination respondTo, final byte[] data) {
		if (!verifyLength(data.length, 8, 8, name))
			return;
		final int iot = (data[0] & 0xff) << 8 | data[1] & 0xff;
		final int instance = (data[2] & 0xff) << 4 | (data[3] & 0xff) >> 4;
		final int pid = (data[3] & 0x0f) << 8 | data[4] & 0xff;
		final int elements = data[5] & 0xff;
		final int start = (data[6] & 0xff) << 8 | data[7] & 0xff;

		logger.trace("{}->{} {} {}({})|{}{} {}..{}", respondTo.getAddress(), dst, name, iot,
				instance, pid, propertyNameByObjectType(iot, pid), start, start + elements - 1);

		ServiceResult<byte[]> sr = ServiceResult.error(ReturnCode.AccessDenied);
		try {
			final int objIndex = objectIndex(iot, instance);
			if (checkPropertyAccess(objIndex, pid, true))
				sr = mgmtSvc.readProperty(respondTo, objIndex, pid, start, elements);
		}
		catch (KNXIllegalArgumentException | KnxPropertyException e) {
			logger.warn("reading property data: {}", e.getMessage());
			sr = ServiceResult.error(ReturnCode.AddressVoid);
		}

		final int length = Math.max(1, sr.result().length);
		final byte[] asdu = Arrays.copyOfRange(data, 0, 8 + length);
		final var returnCode = sr.returnCode();
		asdu[8] = (byte) sr.returnCode().code();

		if (returnCode != ReturnCode.Success)
			asdu[5] = 0;
		else
			System.arraycopy(sr.result(), 0, asdu, 8, length);

		send(respondTo, PropertyExtResponse, asdu, sr.getPriority());
	}

	private void onPropertyExtWrite(final String name, final KNXAddress dst, final Destination respondTo, final byte[] data,
			final boolean confirm) {

		if (!verifyLength(data.length, 9, getMaxApduLength() - 2, name))
			return;
		final int iot = (data[0] & 0xff) << 8 | data[1] & 0xff;
		final int instance = (data[2] & 0xff) << 4 | (data[3] & 0xff) >> 4;
		final int pid = (data[3] & 0xf) << 8 | data[4] & 0xff;
		final int elements = data[5] & 0xff;
		final int start = (data[6] & 0xff) << 8 | data[7] & 0xff;
		final byte[] propertyData = Arrays.copyOfRange(data, 8, data.length);

		logger.trace("{}->{} {} {}({})|{}{} {}..{}: {}", respondTo.getAddress(), dst, name, iot,
				instance, pid, propertyNameByObjectType(iot, pid), start, start + elements - 1, toHex(propertyData, " "));

		ServiceResult<Void> sr = ServiceResult.error(ReturnCode.AccessDenied);
		try {
			final int objIndex = objectIndex(iot, instance);
			if (checkPropertyAccess(objIndex, pid, false))
				sr = mgmtSvc.writeProperty(respondTo, objIndex, pid, start, elements, propertyData);
		}
		catch (KNXIllegalArgumentException | KnxPropertyException e) {
			logger.warn("writing property data: {}", e.getMessage());
			sr = ServiceResult.error(ReturnCode.AddressVoid);
		}
		if (!confirm)
			return;

		final byte[] asdu = Arrays.copyOfRange(data, 0, 9);
		final var returnCode = sr.returnCode();
		if (returnCode != ReturnCode.Success)
			asdu[5] = 0;
		asdu[8] = (byte) returnCode.code();

		send(respondTo, PropertyExtWriteConResponse, asdu, sr.getPriority());
	}

	private void onFunctionPropertyExtCommandOrState(final String name, final KNXAddress dst,
			final Destination respondTo, final boolean isCommand, final byte[] data, final boolean system) {
		if (!verifyLength(data.length, 7, getMaxApduLength() - 2, name)) // min 2 bytes functionInput
			return;
		final int iot = ((data[0] & 0xff) << 8) | data[1] & 0xff;
		final int oi = ((data[2] & 0xff) << 4) | ((data[3] & 0xff) >> 4);
		final int pid = ((data[3] & 0xf) << 8) | (data[4] & 0xff);
		final byte[] functionInput = Arrays.copyOfRange(data, 5, data.length);

		logger.trace("{}->{} {} IOT {} OI {} PID {} {}", respondTo.getAddress(), dst, name, iot, oi, pid,
				toHex(functionInput, " "));


		ServiceResult<byte[]> sr;
		try {
			final int objIndex = objectIndex(iot, oi);
			final var description = device.getInterfaceObjectServer().getDescription(objIndex, pid);
			final int reserved = functionInput[0] & 0xff;

			if (!checkPropertyAccess(objIndex, pid, !isCommand))
				sr = ServiceResult.error(ReturnCode.AccessDenied);
			else if (description.getPDT() == PropertyTypes.PDT_FUNCTION && reserved != 0)
				sr = ServiceResult.error(ReturnCode.DataVoid);
			else if (iot == InterfaceObject.SECURITY_OBJECT && oi == 1 && pid == SecurityObject.Pid.SecurityMode)
				sr = sal.securityMode(isCommand, functionInput);
			else if (description.getPDT() == PropertyTypes.PDT_FUNCTION || description.getPDT() == PropertyTypes.PDT_CONTROL) {
				if (iot == InterfaceObject.SECURITY_OBJECT && oi == 1 && pid == SecurityObject.Pid.SecurityFailuresLog)
					sr = sal.securityFailuresLog(isCommand, functionInput);
				else
					sr = isCommand ? mgmtSvc.functionPropertyCommand(respondTo, objIndex, pid, functionInput)
							: mgmtSvc.readFunctionPropertyState(respondTo, objIndex, pid, functionInput);
			}
			else
				sr = ServiceResult.error(ReturnCode.DataTypeConflict);
		}
		catch (final KnxPropertyException e) {
			logger.warn("{}->{} {} {}({})|{}", respondTo.getAddress(), dst, name, iot, oi, pid, e);
			sr = ServiceResult.error(ReturnCode.AddressVoid);
		}

		final byte[] result = sr.result();
		final ReturnCode rc;
		byte[] state = {};
		if (result.length > getMaxApduLength() - 2 - 5)
			rc = ReturnCode.ExceedsMaxApduLength;
		else {
			rc = sr.returnCode();
			state = result;
		}

		final byte[] asdu = new byte[6 + state.length];
		asdu[0] = (byte) (iot >> 8);
		asdu[1] = (byte) iot;
		asdu[2] = (byte) (oi >> 4);
		asdu[3] = (byte) (((oi & 0xf) << 4) | (pid >> 8));
		asdu[4] = (byte) pid;
		asdu[5] = (byte) rc.code();
		System.arraycopy(state, 0, asdu, 6, state.length);

		final var priority = system ? Priority.SYSTEM : Priority.LOW;
		send(respondTo, FunctionPropertyExtStateResponse, asdu, priority);
	}

	private void onManagement(final int svcType, final byte[] data, final KNXAddress dst, final Destination respondTo)
	{
		final ServiceResult<byte[]> sr = mgmtSvc.management(svcType, data, dst, respondTo, tl);
		if (sr != null)
			sr.run();
	}

	private boolean verifyLength(final int length, final int minExpected, final int maxExpected, final String svcType)
	{
		if (length < minExpected)
			logger.warn(svcType + " SDU of length " + length + " too short, expected " + minExpected);
		else if (length > maxExpected)
			logger.warn(svcType + " SDU of length " + length + " too long, maximum " + maxExpected);
		return length >= minExpected && length <= maxExpected;
	}

	private boolean ignoreOrSchedule(final ServiceResult<?> svc)
	{
		if (svc == null) {
			logger.warn("return value of type ServiceResult required", new KnxRuntimeException("ServiceResult == null"));
			return true;
		}
		if (svc.result() != null) // TODO ideally don't test result for null
			return false;
		svc.run();
		return true;
	}

	private void sendBroadcast(final boolean system, final byte[] apdu, final Priority p, final String service)
	{
		final String type = system ? "system" : "domain";
		logger.trace("{}->[{} broadcast] {} {}", device.getAddress(), type, service, toHex(apdu, " "));
		try {
			final var tsdu = sal.secureData(device.getAddress(), GroupAddress.Broadcast, apdu, securityCtrl).orElse(apdu);
			tl.broadcast(system, p, tsdu);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		catch (KNXLinkClosedException | KNXTimeoutException e) {
			logger.warn("{}->[{} broadcast] {} {}: {}", device.getAddress(), type, service, toHex(apdu, " "),
					e.getMessage());
		}
	}

	private void send(final Destination respondTo, final int service, final byte[] asdu, final Priority p)
	{
		final byte[] apdu = DataUnitBuilder.createAPDU(service, asdu);
		send(respondTo, apdu, p, decodeAPCI(service));
	}

	void send(final Destination respondTo, final byte[] apdu, final Priority p, final String service)
	{
		// if we received a disconnect from the remote, the destination got destroyed to avoid keeping it around
		if (respondTo.getState() == State.Destroyed) {
			logger.warn("cannot respond with {}, {}", service, respondTo);
			return;
		}
		final IndividualAddress dst = respondTo.getAddress();
		logger.trace("{}->{} {} {}", device.getAddress(), dst, service, toHex(apdu, " "));
		try {
			final byte[] tsdu = sal.secureData(device.getAddress(), respondTo.getAddress(), apdu, securityCtrl).orElse(apdu);
			if (respondTo.isConnectionOriented())
				tl.sendData(respondTo, p, tsdu);
			else
				tl.sendData(dst, p, tsdu);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		catch (KNXDisconnectException | KNXLinkClosedException | KNXTimeoutException e) {
			logger.warn("{}->{} {} {}: {}, {}", device.getAddress(), dst, service, toHex(apdu, " "), e.getMessage(),
					respondTo);
		}
	}

	private boolean checkPropertyAccess(final int objectIndex, final int pid, final boolean read) {
		final int objectType = objectType(objectIndex);
		final boolean allowed = AccessPolicies.checkPropertyAccess(objectType, pid, read, sal.isSecurityModeEnabled(),
				securityCtrl);
		if (!allowed)
			logger.info("property {} access to {}|{} denied - {}{}", read ? "read" : "write", objectIndex, pid,
					PropertyClient.getObjectTypeName(objectType), propertyName(objectIndex, pid));
		return allowed;
	}

	private int objectIndex(final int iot, final int oi) {
		final var data = device.getInterfaceObjectServer().getProperty(iot, oi, PID.OBJECT_INDEX, 1, 1);
		return toUnsigned(data);
	}

	private int objectType(final int objectIndex) {
		return toUnsigned(device.getInterfaceObjectServer().getProperty(objectIndex, PID.OBJECT_TYPE, 1, 1));
	}

	private String propertyNameByObjectType(final int iot, final int pid) {
		final InterfaceObjectServer ios = device.getInterfaceObjectServer();
		final PropertyKey key;
		if (pid <= 50)
			key = new PropertyKey(pid);
		else
			key = new PropertyKey(iot, pid);
		final var property = ios.propertyDefinitions().get(key);
		if (property != null)
			return " (" + property.getName() + ")";
		return "";
	}

	private String propertyName(final int objectIndex, final int pid) {
		if (pid <= 50)
			return propertyNameByObjectType(0, pid);

		final var objects = device.getInterfaceObjectServer().getInterfaceObjects();
		final int objectType = objectIndex < objects.length ? objects[objectIndex].getType() : 0;
		return propertyNameByObjectType(objectType, pid);
	}

	private int getMaxApduLength()
	{
		try {
			return DeviceObject.lookup(device.getInterfaceObjectServer()).maxApduLength();
		}
		catch (final KnxPropertyException e) {
			if (!missingApduLength) {
				missingApduLength = true;
				logger.warn("device has no maximum APDU length set (PID.MAX_APDULENGTH), using " + defaultMaxApduLength);
			}
			return defaultMaxApduLength;
		}
	}

	private Map<IndividualAddress, AggregatorProxy> transportLayerProxies() {
		try {
			final var field = tl.getClass().getDeclaredField("proxies");
			field.setAccessible(true);
			@SuppressWarnings("unchecked")
			final var map = (Map<IndividualAddress, AggregatorProxy>) field.get(tl);
			return map;
		}
		catch (NoSuchFieldException | IllegalAccessException e) {
			e.printStackTrace();
		}
		return null;
	}

	// for a max of (2^31)-1
	private static int toUnsigned(final byte[] data)
	{
		if (data.length == 1)
			return data[0] & 0xff;
		if (data.length == 2)
			return (data[0] & 0xff) << 8 | (data[1] & 0xff);
		return (data[0] & 0xff) << 24 | (data[1] & 0xff) << 16 | (data[2] & 0xff) << 8 | (data[3] & 0xff);
	}
}

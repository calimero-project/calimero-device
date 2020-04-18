/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2020 B. Malinowsky

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

import static tuwien.auto.calimero.device.ios.InterfaceObject.ADDRESSTABLE_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.GROUP_OBJECT_TABLE_OBJECT;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;
import java.util.WeakHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.DeviceDescriptor;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIDevMgmt.ErrorCodes;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.mgmt.TransportLayer;
import tuwien.auto.calimero.process.ProcessEvent;

/**
 * Provides the default application layer service logic of a KNX device, without assuming any
 * specific device implementation or restrictions of KNX communication medium.
 *
 * @author B. Malinowsky
 */
public abstract class KnxDeviceServiceLogic implements ProcessCommunicationService, ManagementService
{
	/** The KNX device associated with this service logic. */
	protected KnxDevice device;
	private Logger logger;

	private final DatapointModel<Datapoint> datapoints = new DatapointMap<>();

	// domain can be 2 or 6 bytes, set in setDevice()
	private byte[] domainAddress;

	// authentication
	private static byte[] defaultAuthKey = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
	final byte[][] authKeys = new byte[16][4];
	final WeakHashMap<Destination, Integer> accessLevels = new WeakHashMap<>();
	int minAccessLevel = 3; // or 15

	private final Instant startTime = Instant.now();
	private boolean ignoreReadSNByPowerReset;

	public void setDevice(final KnxDevice device)
	{
		this.device = device;
		logger = (device instanceof BaseKnxDevice) ? ((BaseKnxDevice) device).logger()
				: LoggerFactory.getLogger(KnxDeviceServiceLogic.class);

		domainAddress = new byte[0];
		final KNXNetworkLink link = device.getDeviceLink();
		if (link != null) {
			final KNXMediumSettings settings = link.getKNXMedium();
			if (settings.getMedium() == KNXMediumSettings.MEDIUM_PL110) {
				domainAddress = ((PLSettings) settings).getDomainAddress();
			}
			else if (settings.getMedium() == KNXMediumSettings.MEDIUM_RF) {
				domainAddress = ((RFSettings) settings).getDomainAddress();
			}
		}

		for (int i = 0; i < 16; i++)
			authKeys[i] = defaultAuthKey;
	}

	/**
	 * @return the configured datapoints
	 */
	public final DatapointModel<Datapoint> getDatapointModel()
	{
		return datapoints;
	}

	public abstract void updateDatapointValue(Datapoint ofDp, DPTXlator update);

	/**
	 * Implement this method to provide a requested datapoint value. A subtype might implement this method as follows:
	 *
	 * <pre>
	 * {@code
	 * try {
	 * 	final DPTXlator t = TranslatorTypes.createTranslator(0, ofDp.getDPT());
	 * 	// set the data or value, e.g.:
	 * 	t.setValue( ... provide your datapoint value );
	 * 	return t;
	 * } catch (final KNXException e) {
	 * 	// you might want to handle the case when no DPT translator is available for this datapoint
	 * }}
	 * </pre>
	 *
	 * @param ofDp the datapoint whose value is requested
	 * @return the created DPT translator for the requested datapoint
	 * @throws KNXException if the datapoint value cannot be provided
	 */
	public abstract DPTXlator requestDatapointValue(Datapoint ofDp) throws KNXException;

	/**
	 * Returns the device memory this KNX device should use for any memory-related operations, e.g.,
	 * memory read/write management service.
	 *
	 * @return the device memory
	 */
	byte[] getDeviceMemory()
	{
		return ((BaseKnxDevice) device).deviceMemory();
	}

	/**
	 * @param inProgrammingMode <code>true</code> if device should be set into programming mode,
	 *        <code>false</code> if programming mode should be switched off (if currently set)
	 */
	public final void setProgrammingMode(final boolean inProgrammingMode)
	{
		try {
			final byte state = (byte) (inProgrammingMode ? 1 : 0);
			device.getInterfaceObjectServer().setProperty(0, PID.PROGMODE, 1, 1, state);
		}
		catch (final KnxPropertyException ignore) {}

		final byte[] mem = getDeviceMemory();
		int b = mem[0x60];
		b = inProgrammingMode ? b | 0x01 : b & (~0x01);
		mem[0x60] = (byte) b;
	}

	/**
	 * @return whether the device is in programming mode (<code>true</code>) or not (<code>false</code>)
	 */
	public final boolean inProgrammingMode()
	{
		byte value;
		try {
			value = device.getInterfaceObjectServer().getProperty(0, PID.PROGMODE, 1, 1)[0];
		}
		catch (final KnxPropertyException e) {
			value = getDeviceMemory()[0x60];
		}
		return (value & 0x01) == 0x01;
	}

	@Override
	public ServiceResult groupReadRequest(final ProcessEvent e)
	{
		final GroupAddress dst = e.getDestination();
		final Datapoint dp = getDatapointModel().get(dst);
		if (dp != null) {
			try {
				final DPTXlator t = requestDatapointValue(dp);
				if (t != null)
					return new ServiceResult(t.getData(), t.getTypeSize() == 0);
			}
			catch (KNXException | RuntimeException ex) {
				logger.warn("on group read request {}->{}: {}", e.getSourceAddr(), dst, DataUnitBuilder.toHex(e.getASDU(), " "), ex);
			}
		}
		return null;
	}

	@Override
	public void groupWrite(final ProcessEvent e)
	{
		final GroupAddress dst = e.getDestination();
		final Datapoint dp = getDatapointModel().get(dst);
		if (dp == null)
			return;
		try {
			final DPTXlator t = TranslatorTypes.createTranslator(0, dp.getDPT());
			t.setData(e.getASDU());
			updateDatapointValue(dp, t);
		}
		catch (KNXException | RuntimeException ex) {
			logger.warn("on group write {}->{}: {}, {}", e.getSourceAddr(), dst,
					DataUnitBuilder.toHex(e.getASDU(), " "), ex.getMessage());
		}
	}

	@Override
	public void groupResponse(final ProcessEvent e) {}

	@Override
	public ServiceResult readProperty(final Destination remote, final int objectIndex,
		final int propertyId, final int startIndex, final int elements)
	{
		final InterfaceObjectServer ios = device.getInterfaceObjectServer();
		try {
			final Description d = ios.getDescription(objectIndex, propertyId);
			final Integer level = accessLevel(remote);
			if (level > d.getReadLevel()) {
				logger.warn("deny {} read access to property {}|{} (access level {}, requires {})", remote.getAddress(),
						objectIndex, propertyId, level, d.getReadLevel());
				return null;
			}
		}
		catch (final KnxPropertyException ignore) {
			// getProperty will fail and provide a more accurate error
		}
		final byte[] res = ios.getProperty(objectIndex, propertyId, startIndex, elements);
		if (propertyId == PID.LOAD_STATE_CONTROL) {
			if (res.length > 1)
				return new ServiceResult(res[0]);
		}

		return new ServiceResult(res);
	}

	enum LoadEvent { NoOperation, StartLoading, LoadCompleted, AdditionalLoadControls, Unload }
	enum LoadState { Unloaded, Loaded, Loading, Error, Unloading, LoadCompleting }

	@Override
	public ServiceResult writeProperty(final Destination remote, final int objectIndex,
		final int propertyId, final int startIndex, final int elements, final byte[] data)
	{
		final InterfaceObjectServer ios = device.getInterfaceObjectServer();
		Description d = null;
		try {
			d = ios.getDescription(objectIndex, propertyId);
		}
		catch (final KnxPropertyException e) {
			// try to create description from property definition
			final int objType = ios.getInterfaceObjects()[objectIndex].getType();
			final Property p = ios.propertyDefinitions().get(new PropertyKey(objType, propertyId));
			if (p != null)
				d = new Description(objectIndex, objType, propertyId, 0, p.getPDT(), !p.readOnly(), 0, 1, p.readLevel(),
						p.writeLevel());
		}
		if (d != null && !inProgrammingMode()) {
			if (!d.isWriteEnabled()) {
				logger.warn("property {}|{} is {}", objectIndex, propertyId, CEMIDevMgmt.getErrorMessage(ErrorCodes.READ_ONLY));
				return null;
			}
			final int level = accessLevel(remote);
			if (level > d.getWriteLevel()) {
				logger.warn("deny {} write access to property {}|{} (access level {}, requires {})", remote.getAddress(), objectIndex,
						propertyId, level, d.getWriteLevel());
				return null;
			}
		}

		if (propertyId == PID.LOAD_STATE_CONTROL)
			return changeLoadState(remote, objectIndex, propertyId, startIndex, elements, data);

		// if we set a non-existing property, we won't have a description (it won't show up in a property editor)
		ios.setProperty(objectIndex, propertyId, startIndex, elements, data);
		// handle some special cases
		if (propertyId == PID.PROGMODE)
			setProgrammingMode((data[0] & 0x01) == 0x01);

		return new ServiceResult(data);
	}

	private ServiceResult changeLoadState(final Destination remote, final int objectIndex, final int propertyId,
			final int startIndex, final int elements, final byte[] data) {
		final InterfaceObjectServer ios = device.getInterfaceObjectServer();

		final var event = LoadEvent.values()[data[0] & 0xff];
		logger.debug("load state control event for OI {}: {}", objectIndex, event);
		switch (event) {
		case NoOperation:
			return readProperty(remote, objectIndex, propertyId, startIndex, elements);
		case StartLoading:
			ios.setProperty(objectIndex, propertyId, startIndex, elements, (byte) LoadState.Loading.ordinal());
			return new ServiceResult((byte) LoadState.Loading.ordinal());
		case LoadCompleted:
			ios.setProperty(objectIndex, propertyId, startIndex, elements, (byte) LoadState.Loaded.ordinal());
			return new ServiceResult((byte) LoadState.Loaded.ordinal());
		case AdditionalLoadControls:
			ios.setProperty(objectIndex, propertyId, startIndex, elements, (byte) LoadState.Loading.ordinal());
			return new ServiceResult((byte) LoadState.Loading.ordinal());
		case Unload:
			ios.setProperty(objectIndex, propertyId, startIndex, elements, (byte) LoadState.Loaded.ordinal());
			return new ServiceResult((byte) LoadState.Unloaded.ordinal());
		default:
			throw new Error();
		}
	}

	@Override
	public ServiceResult readPropertyDescription(final int objectIndex, final int propertyId, final int propertyIndex)
	{
		final InterfaceObjectServer ios = device.getInterfaceObjectServer();
		final Description d;
		if (propertyId > 0)
			d = ios.getDescription(objectIndex, propertyId);
		else
			d = ios.getDescriptionByIndex(objectIndex, propertyIndex);
		return new ServiceResult(d.toByteArray());
	}

	private static final int PID_ROUTETABLE_CONTROL = 56;

	@Override
	public ServiceResult functionPropertyCommand(final Destination remote, final int objectIndex, final int propertyId,
		final byte[] command) {
		final int serviceId = command[1] & 0xff;
		final int objectType = device.getInterfaceObjectServer().getInterfaceObjects()[objectIndex].getType();

		if (propertyId == PID.LOAD_STATE_CONTROL)
			return changeLoadState(remote, objectIndex, propertyId, 1, 1, command);

		if (objectType == InterfaceObject.ROUTER_OBJECT) {
			if (propertyId == PID_ROUTETABLE_CONTROL) {
				final int clearRoutingTable = 1;
				final int setRoutingTable = 2;
				final int clearGroupAddresses = 3;
				final int setGroupAddresses = 4;

				if (serviceId == clearRoutingTable)
					return new ServiceResult((byte) 0, (byte) clearRoutingTable);
				if (serviceId == setRoutingTable)
					return new ServiceResult((byte) 0, (byte) setRoutingTable);
				if (serviceId == clearGroupAddresses) {
					final int startAddress = (command[2] & 0xff) << 8 | (command[3] & 0xff);
					final int endAddress = (command[4] & 0xff) << 8 | (command[5] & 0xff);
					return new ServiceResult((byte) 0, (byte) clearGroupAddresses, command[2], command[3], command[4],
							command[5]);
				}
				if (serviceId == setGroupAddresses) {
					final int startAddress = (command[2] & 0xff) << 8 | (command[3] & 0xff);
					final int endAddress = (command[4] & 0xff) << 8 | (command[5] & 0xff);
					return new ServiceResult((byte) 0, (byte) setGroupAddresses, command[2], command[3], command[4],
							command[5]);
				}
			}
		}
		else if (objectType == GROUP_OBJECT_TABLE_OBJECT) {
			final int pidGODiagnostics = 66;
			if (propertyId == pidGODiagnostics)
				return writeGroupObjectDiagnostics(command, serviceId);
		}
		return new ServiceResult(ReturnCode.Error);
	}

	private ServiceResult writeGroupObjectDiagnostics(final byte[] command, final int serviceId) {
		logger.debug("GO diagnostics write service 0x{}", Integer.toHexString(serviceId));

		// write service IDs
		final int setLocalGOValue = 0;
		final int sendGroupValueWrite = 1;
		final int sendLocalGOValueOnBus = 2;
		final int sendGroupValueRead = 3;
		final int limitGroupServiceSenders = 4;

		if (serviceId == limitGroupServiceSenders) // only available in diagnostic operation mode
			return new ServiceResult(ReturnCode.ImpossibleCommand);

		final var dataVoidResult = new ServiceResult(ReturnCode.DataVoid, (byte) serviceId);
		final var invalidCommandResult = new ServiceResult(ReturnCode.InvalidCommand, (byte) serviceId);

		if (serviceId == setLocalGOValue) {
			final int groupObjectNumber = (command[2] & 0xff) << 8 | (command[3] & 0xff);
			final var data = Arrays.copyOfRange(command, 4, command.length);
			// NYI set value, return E_GD_GO_STATUS_VALUE
			return invalidCommandResult;
		}
		else if (serviceId == sendGroupValueWrite) {
			final int flags = command[2] & 0xff;
			if ((flags & 0x7f) > 3)
				return dataVoidResult;

			final var data = Arrays.copyOfRange(command, 5, command.length);
			if (data.length == 0)
				return dataVoidResult;

			final boolean compactApdu = data.length == 1 && (data[0] & 0xff) < 64 && (flags & 0x80) == 0;
			final boolean auth = (flags & 0x01) != 0;
			final boolean conf = (flags & 0x02) != 0;

			final var ga = new GroupAddress(Arrays.copyOfRange(command, 3, 5));
			final var datapoint = datapoints.get(ga);
			if (datapoint == null)
				return dataVoidResult;

			logger.debug("send group value write to {}, conf {} auth {}", ga, conf, auth);
			try {
				final var translator = TranslatorTypes.createTranslator(datapoint.getDPT(), data);
				updateDatapointValue(datapoint, translator);
				sendGroupValue(ga, ProcessServiceNotifier.GROUP_WRITE, compactApdu, data, datapoint.getPriority());
			}
			catch (final KNXException e) {
				logger.warn("GO diagnostics sending group value write to {}", ga, e);
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}

			return new ServiceResult((byte) serviceId);
		}
		else if (serviceId == sendLocalGOValueOnBus) {
			final int groupObjectNumber = (command[2] & 0xff) << 8 | (command[3] & 0xff);
			// NYI send local group value, return E_GD_GO_STATUS_VALUE
			return invalidCommandResult;
		}
		else if (serviceId == sendGroupValueRead) {
			final int flags = command[2] & 0xff;
			if (flags > 3)
				return dataVoidResult;

			final boolean auth = (flags & 0x01) != 0;
			final boolean conf = (flags & 0x02) != 0;
			final var ga = new GroupAddress(Arrays.copyOfRange(command, 3, 5));

			final var datapoint = datapoints.get(ga);
			if (datapoint == null)
				return dataVoidResult;

			logger.info("send group value read to {}, conf {} auth {}", ga, conf, auth);
			try {
				sendGroupValue(ga, ProcessServiceNotifier.GROUP_READ, true, new byte[0], datapoint.getPriority());
				final var translator = requestDatapointValue(datapoint);
				if (translator != null) {
					final boolean compactApdu = translator.getTypeSize() == 0;
					sendGroupValue(ga, ProcessServiceNotifier.GROUP_RESPONSE, compactApdu, translator.getData(),
							datapoint.getPriority());
				}
			}
			catch (final KNXException e) {
				logger.warn("GO diagnostics sending group value read to {}", ga, e);
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
			}
			return new ServiceResult((byte) serviceId);
		}
		return invalidCommandResult;
	}

	private void sendGroupValue(final GroupAddress dst, final int service, final boolean compactApdu, final byte[] data,
			final Priority priority) throws KNXTimeoutException, KNXLinkClosedException, InterruptedException {
		final var plainApdu = compactApdu ? DataUnitBuilder.createLengthOptimizedAPDU(service, data)
				: DataUnitBuilder.createAPDU(service, data);
		final var sal = ((BaseKnxDevice) device).sal;
		final var apdu = sal.secureGroupObject(device.getAddress(), dst, plainApdu).orElse(plainApdu);

		final var link = device.getDeviceLink();
		link.sendRequestWait(dst, priority, apdu);
	}

	@Override
	public ServiceResult readFunctionPropertyState(final Destination remote, final int objectIndex,
		final int propertyId, final byte[] functionInput) {

		final int serviceId = functionInput[1] & 0xff;
		final int objectType = device.getInterfaceObjectServer().getInterfaceObjects()[objectIndex].getType();
		if (objectType == GROUP_OBJECT_TABLE_OBJECT) {
			final int pidGODiagnostics = 66;
			if (propertyId == pidGODiagnostics)
				return readGroupObjectDiagnostics(functionInput, serviceId);
		}

		return ServiceResult.Empty;
	}

	private ServiceResult readGroupObjectDiagnostics(final byte[] functionInput, final int serviceId) {
		logger.debug("GO diagnostics read service 0x{}", Integer.toHexString(serviceId));

		// read service IDs
		final int getGOConfig = 0;
		final int getLocalGOValue = 1;

		final var invalidCommandResult = new ServiceResult(ReturnCode.InvalidCommand, (byte) serviceId);
		if (serviceId == getGOConfig) {
			final int groupObjectNumber = (functionInput[2] & 0xff) << 8 | (functionInput[3] & 0xff);
			// NYI return E_GD_CONFIG
			return invalidCommandResult;
		}
		else if (serviceId == getLocalGOValue) {
			final int groupObjectNumber = (functionInput[2] & 0xff) << 8 | (functionInput[3] & 0xff);
			// NYI return E_GD_GO_STATUS_VALUE
			return invalidCommandResult;
		}
		return invalidCommandResult;
	}

	private static final int addrGroupAddrTable = 0x0116; // max. length 233

	@Override
	public ServiceResult readMemory(final int startAddress, final int bytes)
	{
		final byte[] mem = getDeviceMemory();
		if (startAddress >= mem.length)
			return new ServiceResult(ReturnCode.AddressVoid);
		if (startAddress + bytes >= mem.length)
			return new ServiceResult(ReturnCode.AccessDenied);

		final Collection<Datapoint> c = ((DatapointMap<Datapoint>) datapoints).getDatapoints();
		final int groupAddrTableSize = 3 + c.size() * 2;
		if (startAddress >= addrGroupAddrTable && startAddress < addrGroupAddrTable + groupAddrTableSize) {
			final ByteBuffer bb = ByteBuffer.allocate(groupAddrTableSize);
			bb.put((byte) c.size());
			bb.put(device.getAddress().toByteArray());
			c.forEach(dp -> bb.put(dp.getMainAddress().toByteArray()));
			final int from = startAddress - addrGroupAddrTable;
			return new ServiceResult(Arrays.copyOfRange(bb.array(), from, from + bytes));
		}
		return new ServiceResult(Arrays.copyOfRange(getDeviceMemory(), startAddress, startAddress + bytes));
	}

	@Override
	// TODO revise this method to always use return codes, and not written memory for standard writes
	public ServiceResult writeMemory(final int startAddress, final byte[] data)
	{
		final byte[] mem = getDeviceMemory();
		if (startAddress >= mem.length)
			return new ServiceResult(ReturnCode.AddressVoid);
		if (startAddress + data.length >= mem.length)
			return new ServiceResult(ReturnCode.MemoryError);
		for (int i = 0; i < data.length; i++) {
			final byte b = data[i];
			mem[startAddress + i] = b;
		}
		if (startAddress == 0x60 && data.length == 1)
			setProgrammingMode(data[0] == 1);
		return new ServiceResult(data);
	}

	@Override
	public ServiceResult readAddress()
	{
		if (inProgrammingMode())
			return ServiceResult.Empty;
		return null;
	}

	@Override
	public ServiceResult readAddressSerial(final byte[] serialNo)
	{
		final byte[] myserial = device.getInterfaceObjectServer().getProperty(0, PID.SERIAL_NUMBER, 1, 1);
		if (Arrays.equals(myserial, serialNo)) {
			return ServiceResult.Empty;
		}
		return null;
	}

	@Override
	public void writeAddress(final IndividualAddress newAddress)
	{
		if (inProgrammingMode())
			setDeviceAddress(newAddress);
	}

	@Override
	public void writeAddressSerial(final byte[] serialNo,
		final IndividualAddress newAddress)
	{
		final byte[] myserial = device.getInterfaceObjectServer().getProperty(0, PID.SERIAL_NUMBER, 1, 1);
		if (Arrays.equals(myserial, serialNo))
			setDeviceAddress(newAddress);
	}

	private void setDeviceAddress(final IndividualAddress newAddress) {
		final IndividualAddress old = device.getAddress();
		final KNXMediumSettings settings = device.getDeviceLink().getKNXMedium();
		settings.setDeviceAddress(newAddress);
		if (device instanceof BaseKnxDevice) {
			((BaseKnxDevice) device).setAddress(newAddress);
		}
		logger.info("set new device address {} (old {})", newAddress, old);
	}

	@Override
	public ServiceResult readDomainAddress()
	{
		if (inProgrammingMode())
			return new ServiceResult(domainAddress);
		return null;
	}

	@Override
	public ServiceResult readDomainAddress(final byte[] domain,
		final IndividualAddress startAddress, final int range)
	{
		if (Arrays.equals(domain, domainAddress)) {
			final int raw = device.getAddress().getRawAddress();
			final int start = startAddress.getRawAddress();
			if (raw >= start && raw <= (start + range)) {
				final int wait = (raw - start) * device.getDeviceLink().getKNXMedium().timeFactor();
				logger.trace("read domain address: wait " + wait + " ms before sending response");
				try {
					// NYI iff range < 0xff and we receive a response from another device while waiting, we should
					// cancel our own response
					Thread.sleep(wait);
					return new ServiceResult(domainAddress);
				}
				catch (final InterruptedException e) {
					logger.warn("read domain address got interrupted, response is canceled");
					Thread.currentThread().interrupt();
				}
			}
		}
		return null;
	}

	@Override
	public ServiceResult readDomainAddress(final byte[] startDoA, final byte[] endDoA)
	{
		final long start = ByteBuffer.wrap(startDoA).getLong();
		final long end = ByteBuffer.wrap(endDoA).getLong();
		final long our = ByteBuffer.wrap(domainAddress).getLong();
		if (our >= start && our <= end) {
			final int wait = new Random().nextInt(2001);
			logger.trace("read domain address: wait " + wait + " ms before sending response");
			try {
				Thread.sleep(wait);
				return new ServiceResult(domainAddress);
			}
			catch (final InterruptedException e) {
				logger.warn("read domain address got interrupted, response is canceled");
				Thread.currentThread().interrupt();
			}
		}
		return null;
	}

	@Override
	public void writeDomainAddress(final byte[] domain)
	{
		if (inProgrammingMode()) {
			domainAddress = domain;
			final int pidRFDomainAddress = 82;
			final int pid = domain.length == 2 ? PID.DOMAIN_ADDRESS : pidRFDomainAddress;
			try {
				device.getInterfaceObjectServer().setProperty(0, pid, 1, 1, domain);
			}
			catch (final KnxPropertyException e) {
				logger.error("setting DoA {} in interface object server", DataUnitBuilder.toHex(domain, " "), e);
			}
		}
	}

	@Override
	public ServiceResult readParameter(final int objectType, final int pid, final byte[] info) {
		if (objectType == 0 && pid == PID.SERIAL_NUMBER) {
			final var operand = info[0] & 0xff;
			int maxWaitSeconds = 0;
			if (operand == 1 && inProgrammingMode())
				maxWaitSeconds = 1;
			else if (operand == 2 && device.getAddress().getDevice() == 0xff
					&& (Arrays.equals(new byte[] { 0, (byte) 0xff }, domainAddress)
							|| Arrays.equals(new byte[6], domainAddress)))
				maxWaitSeconds = info[1] & 0xff;
			else if (operand == 3) {
				if (ignoreReadSNByPowerReset || startTime.plus(Duration.ofMinutes(4)).isBefore(Instant.now()))
					return null;
				maxWaitSeconds = info[1] & 0xff;
				ignoreReadSNByPowerReset = maxWaitSeconds < 255;
			}

			if (maxWaitSeconds == 255) // mgmt procedure cancel indicator
				return null;

			if (maxWaitSeconds > 0) {
				// TODO don't block, schedule it
				randomWait(maxWaitSeconds * 1000);
				final var sn = device.getInterfaceObjectServer().getProperty(0, PID.SERIAL_NUMBER, 1, 1);
				return new ServiceResult(sn);
			}
		}
		return ServiceResult.Empty;
	}

	private void randomWait(final int maxWaitMillis) {
		final int wait = (int) (Math.random() * maxWaitMillis);
		logger.debug("add random wait time of " + wait + " ms before response");
		try {
			Thread.sleep(wait);
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public ServiceResult readDescriptor(final int type)
	{
		if (type == 0)
			return new ServiceResult(device.getInterfaceObjectServer().getProperty(0, PID.DEVICE_DESCRIPTOR, 1, 1));
		if (device instanceof BaseKnxDevice) {
			final DeviceDescriptor dd = ((BaseKnxDevice) device).deviceDescriptor();
			if (dd instanceof DeviceDescriptor.DD2)
				return new ServiceResult(dd.toByteArray());
		}
		return null;
	}

	@Override
	public ServiceResult readADC(final int channel, final int consecutiveReads)
	{
		return new ServiceResult(new byte[] { (byte) channel, (byte) consecutiveReads, 0x1, 0x0 });
	}

	@Override
	public ServiceResult writeAuthKey(final Destination remote, final int accessLevel, final byte[] key)
	{
		if (accessLevel >= minAccessLevel)
			return new ServiceResult((byte) minAccessLevel);
		if (accessLevel(remote) > accessLevel)
			return new ServiceResult((byte) 0xff);
		authKeys[accessLevel] = key;
		return new ServiceResult((byte) accessLevel);
	}

	@Override
	public ServiceResult authorize(final Destination remote, final byte[] key)
	{
		final int currentLevel = maximumAccessLevel(key);
		setAccessLevel(remote, currentLevel);
		return new ServiceResult((byte) currentLevel);
	}

	@Override
	public ServiceResult restart(final boolean masterReset, final EraseCode eraseCode, final int channel)
	{
		final String type = masterReset ? "master reset (" + eraseCode + ")" : "basic restart";
		logger.info("received request for {}", type);
		setProgrammingMode(false);
		if (masterReset) {
			final byte errorCode = 0;
			final byte processTimeSeconds = 3;
			return new ServiceResult(errorCode, (byte) 0, processTimeSeconds);
		}
		return null;
	}

	@Override
	public ServiceResult management(final int svcType, final byte[] asdu, final KNXAddress dst,
		final Destination respondTo, final TransportLayer tl)
	{
		logger.info("{}->{} {} {}", respondTo.getAddress(), dst, DataUnitBuilder.decodeAPCI(svcType),
				DataUnitBuilder.toHex(asdu, " "));
		return null;
	}

	@Override
	public boolean isVerifyModeEnabled()
	{
		return false;
	}

	void destinationDisconnected(final Destination remote) {
		final Integer level = accessLevels.remove(remote);
		if (level != null)
			logger.info("endpoint {} disconnected, reset access level {} to {}", remote.getAddress(), level,
					minAccessLevel);
	}

	protected int accessLevel(final Destination remote) {
		final int freeLevel = maximumAccessLevel(defaultAuthKey);
		return accessLevels.getOrDefault(remote, freeLevel);
	}

	// possible access levels [max .. min]: [0 .. 3] or [0 .. 15]
	private int maximumAccessLevel(final byte[] key) {
		for (int i = 0; i < authKeys.length; i++)
			if (Arrays.equals(key, authKeys[i]))
				return i;
		// give minimum level of access to unauthorized clients, or clients with invalid auth
		return minAccessLevel;
	}

	private void setAccessLevel(final Destination remote, final int accessLevel) {
		accessLevels.put(remote, accessLevel);
		logger.info("authorize {} for access level {}", remote.getAddress(), accessLevel);
	}
}

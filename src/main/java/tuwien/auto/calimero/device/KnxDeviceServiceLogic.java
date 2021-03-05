/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2012, 2021 B. Malinowsky

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

import static tuwien.auto.calimero.DataUnitBuilder.toHex;
import static tuwien.auto.calimero.device.ios.InterfaceObject.ADDRESSTABLE_OBJECT;
import static tuwien.auto.calimero.device.ios.InterfaceObject.GROUP_OBJECT_TABLE_OBJECT;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
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
import tuwien.auto.calimero.KnxRuntimeException;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.ReturnCode;
import tuwien.auto.calimero.SerialNumber;
import tuwien.auto.calimero.cemi.CEMIDevMgmt;
import tuwien.auto.calimero.cemi.CEMIDevMgmt.ErrorCodes;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.DatapointMap;
import tuwien.auto.calimero.datapoint.DatapointModel;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.device.ios.DeviceObject;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KnxPropertyException;
import tuwien.auto.calimero.dptxlator.DPTXlator;
import tuwien.auto.calimero.dptxlator.PropertyTypes;
import tuwien.auto.calimero.dptxlator.TranslatorTypes;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.PLSettings;
import tuwien.auto.calimero.link.medium.RFSettings;
import tuwien.auto.calimero.mgmt.Description;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.ManagementClient.EraseCode;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.mgmt.PropertyAccess.PID;
import tuwien.auto.calimero.mgmt.PropertyClient.Property;
import tuwien.auto.calimero.mgmt.PropertyClient.PropertyKey;
import tuwien.auto.calimero.mgmt.TransportLayer;
import tuwien.auto.calimero.process.ProcessEvent;
import tuwien.auto.calimero.secure.SecurityControl;
import tuwien.auto.calimero.secure.SecurityControl.DataSecurity;

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
	private InterfaceObjectServer ios;
	private Logger logger;

	private final DatapointModel<Datapoint> datapoints = new DatapointMap<>();

	// authentication
	private static byte[] defaultAuthKey = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
	final byte[][] authKeys = new byte[16][4];
	final WeakHashMap<Destination, Integer> accessLevels = new WeakHashMap<>();
	int minAccessLevel = 3; // or 15

	private final Instant startTime = Instant.now();
	private boolean ignoreReadSNByPowerReset;

	private volatile boolean verifyMode;


	public void setDevice(final KnxDevice device)
	{
		this.device = device;
		ios = device.getInterfaceObjectServer();
		logger = (device instanceof BaseKnxDevice) ? ((BaseKnxDevice) device).logger()
				: LoggerFactory.getLogger(KnxDeviceServiceLogic.class);

		final KNXNetworkLink link = device.getDeviceLink();
		if (link != null) {
			final KNXMediumSettings settings = link.getKNXMedium();
			if (settings.getMedium() == KNXMediumSettings.MEDIUM_PL110) {
				final byte[] domainAddress = ((PLSettings) settings).getDomainAddress();
				if (!Arrays.equals(domainAddress, new byte[2]) || domainAddress().length == 0)
					setDomainAddress(domainAddress);
			}
			else if (settings.getMedium() == KNXMediumSettings.MEDIUM_RF) {
				final byte[] domainAddress = ((RFSettings) settings).getDomainAddress();
				if (!Arrays.equals(domainAddress, new byte[6]) || domainAddress().length == 0)
					setDomainAddress(domainAddress);
			}
		}

		resetAuthKeys(0);
		syncDatapoints();
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
	 * @param inProgrammingMode <code>true</code> if device should be set into programming mode,
	 *        <code>false</code> if programming mode should be switched off (if currently set)
	 */
	public void setProgrammingMode(final boolean inProgrammingMode)
	{
		try {
			final byte state = (byte) (inProgrammingMode ? 1 : 0);
			ios.setProperty(0, PID.PROGMODE, 1, 1, state);
		}
		catch (final KnxPropertyException ignore) {}

		int b = device.deviceMemory().get(0x60);
		b = inProgrammingMode ? b | 0x01 : b & (~0x01);
		device.deviceMemory().set(0x60, b);
	}

	/**
	 * @return whether the device is in programming mode (<code>true</code>) or not (<code>false</code>)
	 */
	public final boolean inProgrammingMode()
	{
		try {
			return DeviceObject.lookup(ios).programmingMode();
		}
		catch (final KnxPropertyException e) {
			return (device.deviceMemory().get(0x60) & 0x01) == 0x01;
		}
	}

	@Override
	public ServiceResult<byte[]> groupReadRequest(final ProcessEvent e)
	{
		final GroupAddress dst = e.getDestination();
		final Datapoint dp = getDatapointModel().get(dst);
		if (dp != null) {
			try {
				final DPTXlator t = requestDatapointValue(dp);
				if (t != null)
					return new ServiceResult<>(t.getData(), t.getTypeSize() == 0);
			}
			catch (KNXException | RuntimeException ex) {
				logger.warn("on group read request {}->{}: {}", e.getSourceAddr(), dst, toHex(e.getASDU(), " "), ex);
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
			logger.warn("on group write {}->{}: {}, {}", e.getSourceAddr(), dst, toHex(e.getASDU(), " "),
					ex.getMessage());
		}
	}

	@Override
	public void groupResponse(final ProcessEvent e) {}

	@Override
	public ServiceResult<byte[]> readProperty(final Destination remote, final int objectIndex,
		final int propertyId, final int startIndex, final int elements)
	{
		try {
			final Description d = ios.getDescription(objectIndex, propertyId);
			if (d.getPDT() == PropertyTypes.PDT_FUNCTION)
				return ServiceResult.error(ReturnCode.DataVoid);
			final Integer level = accessLevel(remote);
			if (level > d.getReadLevel()) {
				logger.warn("deny {} read access to property {}|{} (access level {}, requires {})", remote.getAddress(),
						objectIndex, propertyId, level, d.getReadLevel());
				return ServiceResult.error(ReturnCode.AccessDenied);
			}
		}
		catch (final KnxPropertyException ignore) {
			// getProperty will fail and provide a more accurate error
		}
		final byte[] res = ios.getProperty(objectIndex, propertyId, startIndex, elements);
		return ServiceResult.of(res);
	}

	enum LoadEvent { NoOperation, StartLoading, LoadCompleted, AdditionalLoadControls, Unload }
	public enum LoadState { Unloaded, Loaded, Loading, Error, Unloading, LoadCompleting }

	// Helper for load state machine of BIM M112
	// DM_LoadStateMachineVerify_RCo_Mem
	private static class BimM112 {
		// address of mgmt control
		private static final int MgmtControl = 0x0104;
		// address of run control
		private static final int RunControl = 0x0103;

		static boolean isMgmtControl(final int startAddress) {
			return startAddress == MgmtControl;
		}

		// addresses of load states
		private static final int LsAddressTable = 0xb6ea;
		private static final int LsAssociationTable = 0xb6eb;
		private static final int LsApplicationTable = 0xb6ec;
		private static final int LsPeiProgram = 0xb6ed;

		private static int loadStateAddress(final int stateMachineIndex) {
			switch (stateMachineIndex) {
			case 1: return LsAddressTable;
			case 2: return LsAssociationTable;
			case 3: return LsApplicationTable;
			case 4: return LsPeiProgram;
			default: return 0;
			}
		}

		static void onLoadEvent(final KnxDeviceServiceLogic logic, final byte[] data) {
			final int stateMachineAndEvent = data[0] & 0xff;

			final int stateMachine = stateMachineAndEvent >> 4;
			final int addr = loadStateAddress(stateMachine);

			final var event = LoadEvent.values()[stateMachineAndEvent & 0xf];
			final var state = nextLoadState(event);
			logic.logger.debug("state machine {} (0x{}) event {} -> load state {}", stateMachine,
					Integer.toHexString(addr), event, state);
			logic.writeMemory(addr, new byte[] { (byte) state.ordinal() });
		}

		// write addresses of run states
		private static final int RsAppProgram = 0x0101;
		private static final int RsPeiProgram = 0x0102;
	}


	@Override
	public ServiceResult<Void> writeProperty(final Destination remote, final int objectIndex,
		final int propertyId, final int startIndex, final int elements, final byte[] data)
	{
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
				return ServiceResult.error(ReturnCode.AccessReadOnly);
			}
			final int level = accessLevel(remote);
			if (level > d.getWriteLevel()) {
				logger.warn("deny {} write access to property {}|{} (access level {}, requires {})", remote.getAddress(),
						objectIndex, propertyId, level, d.getWriteLevel());
				return ServiceResult.error(ReturnCode.AccessDenied);
			}
		}

		if (propertyId == PID.LOAD_STATE_CONTROL) {
			final var state = changeLoadState(remote, objectIndex, propertyId, startIndex, elements, data);
			return castResult(state);
		}

		ios.setProperty(objectIndex, propertyId, startIndex, elements, data);
		// handle some special cases
		if (objectIndex == 0 && propertyId == PID.PROGMODE)
			setProgrammingMode((data[0] & 0x01) == 0x01);
		// verify mode control is used by mask 0020h, 0021h, 0701h, 0705h System B, System 300, mask 091Ah
		if (objectIndex == 0 && propertyId == PID.DEVICE_CONTROL)
			verifyMode = (data[0] & 0x04) != 0;

		return ServiceResult.empty();
	}

	@SuppressWarnings("unchecked")
	private static <T> ServiceResult<T> castResult(final ServiceResult<byte[]> ls) { return (ServiceResult<T>) ls; }

	private static LoadState nextLoadState(final LoadEvent event) {
		switch (event) {
		case NoOperation: return LoadState.Error; // ??? return current state
		case StartLoading: return LoadState.Loading;
		case LoadCompleted: return LoadState.Loaded;
		case AdditionalLoadControls: return LoadState.Loading;
		case Unload: return LoadState.Unloaded;
		default: throw new IllegalStateException();
		}
	}

	private ServiceResult<byte[]> changeLoadState(final Destination remote, final int objectIndex, final int propertyId,
			final int startIndex, final int elements, final byte[] data) {

		final var event = LoadEvent.values()[data[0] & 0xff];
		logger.debug("load state control event for OI {}: {}", objectIndex, event);

		if (event == LoadEvent.NoOperation)
			return ServiceResult.of(readProperty(remote, objectIndex, propertyId, startIndex, elements).result());
		final var loadState = nextLoadState(event);
		ios.setProperty(objectIndex, propertyId, startIndex, elements, (byte) loadState.ordinal());
		return new ServiceResult<byte[]>((byte) loadState.ordinal());
	}

	@Override
	public ServiceResult<Description> readPropertyDescription(final int objectIndex, final int propertyId,
			final int propertyIndex) {
		if (propertyId > 0)
			return ServiceResult.of(ios.getDescription(objectIndex, propertyId));
		return ServiceResult.of(ios.getDescriptionByIndex(objectIndex, propertyIndex));
	}

	private static final int PID_ROUTETABLE_CONTROL = 56;

	@Override
	public ServiceResult<byte[]> functionPropertyCommand(final Destination remote, final int objectIndex, final int propertyId,
		final byte[] command) {
		final int serviceId = command[1] & 0xff;
		final int objectType = ios.getInterfaceObjects()[objectIndex].getType();

		if (propertyId == PID.LOAD_STATE_CONTROL)
			return changeLoadState(remote, objectIndex, propertyId, 1, 1, command);

		if (objectType == InterfaceObject.ROUTER_OBJECT) {
			if (propertyId == PID_ROUTETABLE_CONTROL) {
				final int clearRoutingTable = 1;
				final int setRoutingTable = 2;
				final int clearGroupAddresses = 3;
				final int setGroupAddresses = 4;

				if (serviceId == clearRoutingTable)
					return new ServiceResult<byte[]>((byte) 0, (byte) clearRoutingTable);
				if (serviceId == setRoutingTable)
					return new ServiceResult<byte[]>((byte) 0, (byte) setRoutingTable);
				if (serviceId == clearGroupAddresses) {
					final int startAddress = (command[2] & 0xff) << 8 | (command[3] & 0xff);
					final int endAddress = (command[4] & 0xff) << 8 | (command[5] & 0xff);
					return new ServiceResult<byte[]>((byte) 0, (byte) clearGroupAddresses, command[2], command[3],
							command[4], command[5]);
				}
				if (serviceId == setGroupAddresses) {
					final int startAddress = (command[2] & 0xff) << 8 | (command[3] & 0xff);
					final int endAddress = (command[4] & 0xff) << 8 | (command[5] & 0xff);
					return new ServiceResult<byte[]>((byte) 0, (byte) setGroupAddresses, command[2], command[3],
							command[4], command[5]);
				}
			}
		}
		else if (objectType == GROUP_OBJECT_TABLE_OBJECT) {
			final int pidGODiagnostics = 66;
			if (propertyId == pidGODiagnostics)
				return writeGroupObjectDiagnostics(command, serviceId);
		}
		return ServiceResult.error(ReturnCode.Error);
	}

	private ServiceResult<byte[]> writeGroupObjectDiagnostics(final byte[] command, final int serviceId) {
		logger.debug("GO diagnostics write service 0x{}", Integer.toHexString(serviceId));

		// write service IDs
		final int setLocalGOValue = 0;
		final int sendGroupValueWrite = 1;
		final int sendLocalGOValueOnBus = 2;
		final int sendGroupValueRead = 3;
		final int limitGroupServiceSenders = 4;

		if (serviceId == limitGroupServiceSenders) // only available in diagnostic operation mode
			return ServiceResult.error(ReturnCode.ImpossibleCommand);

		final var dataVoidResult = ServiceResult.of(ReturnCode.DataVoid, (byte) serviceId);
		final var invalidCommandResult = ServiceResult.of(ReturnCode.InvalidCommand, (byte) serviceId);

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

			final var secCtrl = SecurityControl.of(conf ? DataSecurity.AuthConf : auth ? DataSecurity.Auth : DataSecurity.None, false);
			logger.debug("send group value write to {} ({})", ga, secCtrl);
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

			return new ServiceResult<byte[]>((byte) serviceId);
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

			final var secCtrl = SecurityControl.of(conf ? DataSecurity.AuthConf : auth ? DataSecurity.Auth : DataSecurity.None, false);
			logger.info("send group value read to {} ({})", ga, secCtrl);
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
			return new ServiceResult<byte[]>((byte) serviceId);
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
	public ServiceResult<byte[]> readFunctionPropertyState(final Destination remote, final int objectIndex,
		final int propertyId, final byte[] functionInput) {

		final int serviceId = functionInput[1] & 0xff;
		final int objectType = ios.getInterfaceObjects()[objectIndex].getType();
		if (objectType == GROUP_OBJECT_TABLE_OBJECT) {
			final int pidGODiagnostics = 66;
			if (propertyId == pidGODiagnostics)
				return readGroupObjectDiagnostics(functionInput, serviceId);
		}

		return ServiceResult.error(ReturnCode.InvalidCommand);
	}

	private ServiceResult<byte[]> readGroupObjectDiagnostics(final byte[] functionInput, final int serviceId) {
		logger.debug("GO diagnostics read service 0x{}", Integer.toHexString(serviceId));

		// read service IDs
		final int getGOConfig = 0;
		final int getLocalGOValue = 1;

		final var invalidCommandResult = ServiceResult.of(ReturnCode.InvalidCommand, (byte) serviceId);
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
	public ServiceResult<byte[]> readMemory(final int startAddress, final int bytes)
	{
		final int size = device.deviceMemory().size();
		if (startAddress >= size)
			return ServiceResult.error(ReturnCode.AddressVoid);
		if (startAddress + bytes >= size)
			return ServiceResult.error(ReturnCode.AccessDenied);

		final byte[] mem = device.deviceMemory().get(0, size);
		final Collection<Datapoint> c = ((DatapointMap<Datapoint>) datapoints).getDatapoints();
		final int groupAddrTableSize = 4 + c.size() * 2;
		if (startAddress >= addrGroupAddrTable && startAddress < addrGroupAddrTable + groupAddrTableSize) {
			final ByteBuffer bb = ByteBuffer.allocate(groupAddrTableSize);
			bb.putShort((byte) c.size());
			bb.put(device.getAddress().toByteArray());
			c.forEach(dp -> bb.put(dp.getMainAddress().toByteArray()));
			final int from = startAddress - addrGroupAddrTable;
			return ServiceResult.of(Arrays.copyOfRange(bb.array(), from, from + bytes));
		}
		return ServiceResult.of(Arrays.copyOfRange(mem, startAddress, startAddress + bytes));
	}

	@Override
	public ServiceResult<Void> writeMemory(final int startAddress, final byte[] data)
	{
		final int size = device.deviceMemory().size();
		if (startAddress >= size)
			return ServiceResult.error(ReturnCode.AddressVoid);
		if (startAddress + data.length >= size)
			return ServiceResult.error(ReturnCode.MemoryError);

		if (BimM112.isMgmtControl(startAddress)) {
			final var dd = readDescriptor(0).result();
			if (dd == DeviceDescriptor.DD0.TYPE_0700 || dd == DeviceDescriptor.DD0.TYPE_0701) {
				BimM112.onLoadEvent(this, data);
				return new ServiceResult<>();
			}
		}

		if (startAddress == 0x60 && data.length == 1)
			setProgrammingMode(data[0] == 1);
		else
			device.deviceMemory().set(startAddress, data);
		return ServiceResult.empty();
	}

	@Override
	public ServiceResult<Boolean> readAddress() {
		return ServiceResult.of(inProgrammingMode());
	}

	@Override
	public ServiceResult<Boolean> readAddressSerial(final SerialNumber serialNo) {
		final var myserial = DeviceObject.lookup(ios).serialNumber();
		return ServiceResult.of(myserial.equals(serialNo));
	}

	@Override
	public void writeAddress(final IndividualAddress newAddress)
	{
		if (inProgrammingMode())
			setDeviceAddress(newAddress);
	}

	@Override
	public void writeAddressSerial(final SerialNumber serialNo, final IndividualAddress newAddress) {
		final var myserial = DeviceObject.lookup(ios).serialNumber();
		if (myserial.equals(serialNo))
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
	public ServiceResult<Boolean> readDomainAddress() {
		return ServiceResult.of(inProgrammingMode());
	}

	@Override
	public ServiceResult<Boolean> readDomainAddress(final byte[] domain, final IndividualAddress startAddress,
			final int range) {
		final byte[] domainAddress = domainAddress();
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
					return ServiceResult.of(true);
				}
				catch (final InterruptedException e) {
					logger.warn("read domain address got interrupted, response is canceled");
					Thread.currentThread().interrupt();
				}
			}
		}
		return ServiceResult.of(false);
	}

	@Override
	public ServiceResult<Boolean> readDomainAddress(final byte[] startDoA, final byte[] endDoA)
	{
		final long start = unsigned(startDoA);
		final long end = unsigned(endDoA);
		final byte[] domainAddress = domainAddress();
		final long our = unsigned(domainAddress);
		if (our >= start && our <= end) {
			if (randomWait("read domain address", 2001))
				return ServiceResult.of(true);
		}
		return ServiceResult.of(false);
	}

	@Override
	public void writeDomainAddress(final byte[] domain)
	{
		if (inProgrammingMode()) {
			final var settings = device.getDeviceLink().getKNXMedium();
			if (domain.length == 2) {
				((PLSettings) settings).setDomainAddress(domain);
			}
			else {
				((RFSettings) settings).setDomainAddress(domain);
			}
			setDomainAddress(domain);
		}
	}

	private void setDomainAddress(final byte[] domain) {
		try {
			DeviceObject.lookup(ios).setDomainAddress(domain);
		}
		catch (final KnxPropertyException e) {
			logger.warn("setting DoA {} in interface object server", toHex(domain, " "), e);
		}
	}

	private byte[] domainAddress() {
		try {
			return DeviceObject.lookup(ios).domainAddress(domainType());
		}
		catch (final KnxPropertyException e) {
			logger.warn("reading DoA", e);
		}
		return new byte[0];
	}

	private boolean domainType() {
		final var settings = device.getDeviceLink().getKNXMedium();
		if (settings instanceof PLSettings)
			return false;
		else if (settings instanceof RFSettings)
			return true;
		throw new KnxPropertyException(settings + " does not have domain");
	}

	@Override
	public ServiceResult<byte[]> readParameter(final int objectType, final int pid, final byte[] info) {
		if (objectType == 0 && pid == PID.SERIAL_NUMBER) {
			final var operand = info[0] & 0xff;
			int maxWaitSeconds = 0;
			if (operand == 1 && inProgrammingMode())
				maxWaitSeconds = 1;
			else if (operand == 2 && device.getAddress().getDevice() == 0xff
					&& (Arrays.equals(new byte[] { 0, (byte) 0xff }, domainAddress())
							|| Arrays.equals(new byte[6], domainAddress())))
				maxWaitSeconds = info[1] & 0xff;
			else if (operand == 3) {
				if (ignoreReadSNByPowerReset || startTime.plus(Duration.ofMinutes(4)).isBefore(Instant.now()))
					return new ServiceResult<>();
				maxWaitSeconds = info[1] & 0xff;
				ignoreReadSNByPowerReset = maxWaitSeconds < 255;
			}

			if (maxWaitSeconds == 255) // mgmt procedure cancel indicator
				return new ServiceResult<>();

			if (maxWaitSeconds > 0) {
				// TODO don't block, schedule it
				randomWait("read parameter - serial number", maxWaitSeconds * 1000);
				final var sn = DeviceObject.lookup(ios).serialNumber();
				return ServiceResult.of(sn.array());
			}
		}
		return ServiceResult.empty();
	}

	private boolean randomWait(final String svc, final int maxWaitMillis) {
		final int wait = (int) (Math.random() * maxWaitMillis);
		logger.trace("{}: add random wait of {} ms before response", svc, wait);
		try {
			Thread.sleep(wait);
			return true;
		}
		catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		return false;
	}

	@Override
	public ServiceResult<DeviceDescriptor> readDescriptor(final int type)
	{
		if (type == 0)
			return ServiceResult.of(DeviceObject.lookup(ios).deviceDescriptor());
		if (device instanceof BaseKnxDevice) {
			final DeviceDescriptor dd = ((BaseKnxDevice) device).deviceDescriptor();
			if (dd instanceof DeviceDescriptor.DD2)
				return ServiceResult.of(dd);
		}
		throw new KnxRuntimeException("cannot provide DD2");
	}

	@Override
	public ServiceResult<Integer> readADC(final int channel, final int consecutiveReads)
	{
		final int peiType = 10;
		// peiType = (10 * adcValue + 60) / 128 / consecutiveReads;
		final int adcValue = Math.max(0, (peiType * 128 * consecutiveReads - 60) / 10);
		return ServiceResult.of(adcValue);
	}

	@Override
	public ServiceResult<Integer> writeAuthKey(final Destination remote, final int accessLevel, final byte[] key)
	{
		if (accessLevel >= minAccessLevel)
			return ServiceResult.of(minAccessLevel);
		if (accessLevel(remote) > accessLevel)
			return ServiceResult.of(0xff);
		authKeys[accessLevel] = key;
		return ServiceResult.of(accessLevel);
	}

	@Override
	public ServiceResult<Integer> authorize(final Destination remote, final byte[] key)
	{
		final int currentLevel = maximumAccessLevel(key);
		setAccessLevel(remote, currentLevel);
		return ServiceResult.of(currentLevel);
	}

	@Override
	public ServiceResult<Duration> restart(final boolean masterReset, final EraseCode eraseCode, final int channel)
	{
		final String type = masterReset ? "master reset (" + eraseCode + ")" : "basic restart";
		logger.info("received request for {}", type);
		setProgrammingMode(false);
		syncDatapoints();
		if (masterReset) {

			// increase download counter except for confirmed restart
			if (eraseCode.ordinal() > 1) {
				final int pidDownloadCounter = 30;
				try {
					final double counter = ios.getPropertyTranslated(0, pidDownloadCounter, 1, 1).getNumericValue();
					final double inc = Math.min(0xffff, counter + 1);
					ios.setProperty(0, pidDownloadCounter, 1, 1,
							ByteBuffer.allocate(2).putShort((short) inc).array());
				}
				catch (KNXException | KnxPropertyException e) {
					e.printStackTrace();
				}
			}

			if (eraseCode == EraseCode.FactoryReset || eraseCode == EraseCode.FactoryResetWithoutIndividualAddress) {
				final int accessLevel = accessLevel(null);
				resetAuthKeys(accessLevel);
			}

			final var processTime = Duration.ofSeconds(3);
			return ServiceResult.of(processTime);
		}
		return null;
	}

	private void resetAuthKeys(final int maxAccessLevel) {
		for (int i = maxAccessLevel; i < 16; i++)
			authKeys[i] = defaultAuthKey;
	}

	@Override
	public ServiceResult<byte[]> management(final int svcType, final byte[] asdu, final KNXAddress dst,
		final Destination respondTo, final TransportLayer tl)
	{
		logger.info("{}->{} {} {}", respondTo.getAddress(), dst, DataUnitBuilder.decodeAPCI(svcType), toHex(asdu, " "));
		return null;
	}

	@Override
	public boolean isVerifyModeEnabled()
	{
		return verifyMode;
	}

	private void syncDatapoints() {
		syncTableWithMemory(InterfaceObject.ADDRESSTABLE_OBJECT);
		syncTableWithMemory(InterfaceObject.ASSOCIATIONTABLE_OBJECT);
		syncTableWithMemory(GROUP_OBJECT_TABLE_OBJECT);

		final byte[] table = ios.getProperty(ADDRESSTABLE_OBJECT, 1, PID.TABLE, 1, Integer.MAX_VALUE);
		final var buffer = ByteBuffer.wrap(table);

		while (buffer.hasRemaining()) {
			final var group = new GroupAddress(buffer.getShort() & 0xffff);
			if (!datapoints.contains(group)) {
				try {
					final var optFlags = groupAddressIndex(group)
							.flatMap(this::groupObjectIndex).map(groupObjectIndex -> ios
									.getProperty(GROUP_OBJECT_TABLE_OBJECT, 1, PID.TABLE, groupObjectIndex, 1))
							.map(KnxDeviceServiceLogic::groupObjectDescriptor);
					if (optFlags.isEmpty())
						continue;
					final var flags = optFlags.get();

					final var mainType = TranslatorTypes.ofBitSize((int) flags[0]).get(0);
					final String dpt = mainType.getSubTypes().keySet().iterator().next();
					final var dp = new StateDP(group, group.toString(), mainType.getMainNumber(), dpt);
					dp.setPriority((Priority) flags[1]);
					datapoints.add(dp);
				}
				catch (final KnxPropertyException | KNXException e) {
					e.printStackTrace();
				}
			}
		}
	}

	private void syncTableWithMemory(final int objectType) {
		final int objectInstance = 1;
		final int ref = (int) unsigned(ios.getProperty(objectType, objectInstance, PID.TABLE_REFERENCE, 1, 1));

		final int idx = (int) unsigned(ios.getProperty(objectType, objectInstance, PID.OBJECT_INDEX, 1, 1));
		final var description = ios.getDescription(idx, PID.TABLE);
		final int typeSize = PropertyTypes.bitSize(description.getPDT()).orElse(16) / 8;

		final byte[] tableSize = device.deviceMemory().get(ref, 2);
		final int size = (tableSize[0] & 0xff) << 8 | tableSize[1] & 0xff;
		if (size > 0) {
			final int max = size;
			ios.setDescription(new Description(idx, 0, PID.TABLE, 0, 0, true, 0, max, 3, 3), true);
			final byte[] data = device.deviceMemory().get(ref + 2, size * typeSize);
			ios.setProperty(objectType, objectInstance, PID.TABLE, 1, size, data);
		}
	}

	private Optional<Integer> groupAddressIndex(final GroupAddress address) {
		return groupAddressIndex(ios, address);
	}

	// returns 1-based index of address in group address table
	static Optional<Integer> groupAddressIndex(final InterfaceObjectServer ios, final GroupAddress address) {
		final byte[] addresses = ios.getProperty(ADDRESSTABLE_OBJECT, 1, PropertyAccess.PID.TABLE, 1,
				Integer.MAX_VALUE);

		final var addr = address.toByteArray();
		final int entrySize = addr.length;
		for (int offset = 0; offset < addresses.length; offset += entrySize) {
			if (Arrays.equals(addr, 0, addr.length, addresses, offset, offset + 2))
				return Optional.of(offset / entrySize + 1);
		}
		return Optional.empty();
	}

	// returns 1-based index of group object table
	private Optional<Integer> groupObjectIndex(final int groupAddressIndex) {
		return groupObjectIndex(ios, groupAddressIndex);
	}

	static Optional<Integer> groupObjectIndex(final InterfaceObjectServer ios, final int groupAddressIndex) {
		final byte[] assoc = ios.getProperty(InterfaceObject.ASSOCIATIONTABLE_OBJECT, 1, PropertyAccess.PID.TABLE, 1,
				Integer.MAX_VALUE);
		final var buffer = ByteBuffer.wrap(assoc);
		while (buffer.hasRemaining()) {
			if ((buffer.getShort() & 0xffff) == groupAddressIndex)
				return Optional.of(buffer.getShort() & 0xffff);
			buffer.getShort();
		}
		return Optional.empty();
	}

	private static Object[] groupObjectDescriptor(final byte[] descriptor) {
		final int flags = descriptor[0] & 0xff;
		final int priority = flags & 0x3;
		final boolean enable = (flags & 0x04) != 0;
		final boolean responder = enable && (flags & 0x08) != 0;
		final boolean update = (flags & 0x80) != 0;

		final int bitsize = valueFieldTypeToBits(descriptor[1] & 0xff);

		return new Object[] { bitsize, Priority.get(priority), responder, update };
	}

	static byte[] groupObjectDescriptor(final String dpt, final Priority p, final boolean responder,
			final boolean update) {
		final int enableFlag = 0x04;
		final int respondFlag = responder ? 0x08 : 0;
		final int updateFlag = update ? 0x80 : 0;
		int bitsize = 1;
		try {
			bitsize = TranslatorTypes.createTranslator(dpt).bitSize();
		}
		catch (final KNXException e) {
			e.printStackTrace();
		}
		return new byte[] { (byte) (updateFlag | respondFlag | enableFlag | p.value), (byte) bitsToValueFieldType(bitsize) };
	}

	// decodes group object descriptor value field type into PDT bit size
	private static int valueFieldTypeToBits(final int code) {
		final int[] lowerFieldTypes = { 1, 2, 3, 4, 5, 6, 7, 8,
			2 * 8, 3 * 8, 4 * 8, 6 * 8, 8 * 8, 10 * 8, 14 * 8,
			5 * 8, 7 * 8, 9 * 8, 11 * 8, 12 * 8, 13 * 8
		};

		if (code < lowerFieldTypes.length)
			return lowerFieldTypes[code];
		if (code == 255)
			return 252 * 8;
		return (code - 6) * 8;
	}

	// encodes a PDT bit size into a group object descriptor value field type
	private static int bitsToValueFieldType(final int bitsize) {
		if (bitsize < 9)
			return bitsize - 1;
		final int bytes = bitsize / 8;
		switch (bytes) {
			case 2: return 8;
			case 3: return 9;
			case 4: return 10;
			case 6: return 11;
			case 8: return 12;
			case 10: return 13;
			case 14: return 14;
			case 252: return 255;
		}
		return bytes + 6;
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

	private static long unsigned(final byte[] data) {
		long v = 0;
		for (final byte b : data)
			v = (v << 8) + (b & 0xff);
		return v;
	}
}
